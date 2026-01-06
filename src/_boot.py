import network
import time
import tools
import machine
import binascii
import asyncio


# Netzwerkeinstellungen für LAN mit DHCP konfigurieren (siehe nächster Abschnitt)
def setup_lan():
    hostname = tools.config.get("hostname")
    network.hostname(hostname)
    lan = network.LAN(mdc = machine.Pin(23), mdio = machine.Pin(18), power = machine.Pin(12), phy_type = network.PHY_LAN8720, phy_addr = 0)
    lan.active(True)
    #lan.ifconfig('dhcp')
    print("Warte auf Netzwerkverbindung...")
    for i in range(10):
        if lan.isconnected():
            break
        time.sleep(1)
    if lan.isconnected():
        print("Verbunden! IP-Adresse:", lan.ifconfig()[0])
    else:
        print("Keine Netzverbindung!")

# Rufe setup_lan auf, um das LAN mit DHCP zu aktivieren
setup_lan()

from microdot import Microdot, Response
from microdot.utemplate import Template

app = Microdot()
Response.default_content_type = 'text/html'


# Hilfsfunktion für Basic Authentication
def check_basic_auth(request):
    auth = request.headers.get('Authorization')
    if not auth:
        return False

    # Erwartet "Basic <base64-encoded username:password>"
    try:
        auth_type, credentials = auth.split(" ")
        if auth_type != "Basic":
            return False

        # Base64-Dekodierung der Anmeldeinformationen
        decoded_credentials = binascii.a2b_base64(credentials).decode("utf-8")
        username, password = decoded_credentials.split(":")

        return username == tools.config.get('username') and password == tools.config.get('password')
    except Exception:
        return False
    

# Authentifizierungs-Wrapper für geschützte Routen
def requires_auth(handler):
    async def wrapper(request, *args, **kwargs):
        if not check_basic_auth(request):
            return Response(status_code=401, headers={
                'WWW-Authenticate': 'Basic realm="Authentication Required"'
            }, body="Unauthorized")
        return await handler(request, *args, **kwargs)
    return wrapper


@app.route('/test')
@requires_auth
async def index(request):
    print('/test GET')
    return Template("dummy.html").render(name='user')


@app.route('/')
@requires_auth
async def index(request):
    print('/ GET')
    
    # read registered tag information and convert the UID to a string
    store = tools.AuthorizedRFIDStore()
    tags = [
        [tools.uid2str(i[0]),] + i[1:]
        for i in store.get_all()
    ]
    print(tags)
    
    # render the HTML page
    return Template("main.html").render(tags=tags)


@app.put('/tags')
@requires_auth
async def add_tag(request):
    print('/tags PUT')
    new_tag = request.json
    print('  {}'.format(new_tag))
    
    if 'username' in new_tag and 'timestamp' in new_tag and 'collmex_id' in new_tag and 'password' in new_tag:
        uid = await tools.read_uid()
        print(f'  UID: {uid}')
        if uid is None:
            return {'success': False}, 400
        else:
            try:
                print('  setting custom key..')
                await tools.set_key_for_all_sectors(tools.CUSTOM_KEY, uid=uid)
                print('  writing data to rfid tag..')
                await tools.write_data(new_tag['username'], new_tag['collmex_id'], new_tag['password'], uid=uid)
                store = tools.AuthorizedRFIDStore()
                store.add(uid, new_tag['username'], new_tag['collmex_id'], new_tag['timestamp'])
                print('  success :)')
                return {'success': True}, 200
            except tools.RFIDException as exc:
                print('  failure :(')
                print(exc)
                return {
                    'success': False,
                    'msg': str(exc)
                }, 400
    else:
        return {
            'success': False,
            'msg': 'Not all values have been specified!'
        }, 400
    

@app.delete('/tags')
@requires_auth
async def delete_tag(request):
    print('/tags DELETE')
    params = request.args
    print('  {}'.format(params))
    
    try:
        if 'uid' in params:
            uid = tools.hexstr2values(params['uid'])
        else:
            uid = await tools.read_uid()
            
        if 'reset' in params and params['reset'].lower() == 'true':
            print('  deleting all sectors..')
            await tools.write_data('', '', '', meta_data='', uid=uid)
            print('  setting default key..')
            await tools.set_key_for_all_sectors(tools.DEFAULT_KEY, uid=uid)

        store = tools.AuthorizedRFIDStore()
        store.remove(uid)
        
        print('  success :)')
        return {'success': True}, 200
    except tools.RFIDException as exc:
        print('  failure :(')
        print(exc)
        return {
            'success': False,
            'msg': str(exc)
        }, 400
    


print("Starting RFID reading...")
tools.start_rfid_reading()


async def _start_web_server():
    print("Starting web server...")
    #app.run(port=80)
    await app.start_server(debug=False, port=80)


def start_web_server():
    loop = asyncio.get_event_loop()
    loop.create_task(_start_web_server())
    loop.run_forever()


# do not start the web server if the OLIMEX button has been pressed
button_pin = machine.Pin(34, machine.Pin.IN)
time.sleep(0.1)
if button_pin.value() == 0:
    print("Debug mode: Button pressed, web server will NOT start.")
else:
    start_web_server()

