#!/bin/bash

if [ ! -f websocket.py ];
then
  wget 'https://raw.githubusercontent.com/google/syzygy/master/third_party/websocket-client/websocket.py' -O websocket.py
fi

if [ ! -f websocket_server.py ];
then
  wget 'https://raw.githubusercontent.com/Pithikos/python-websocket-server/master/websocket_server/websocket_server.py' -O websocket_server.py
fi

sed '882,$d' websocket.py | sed '1,58d' > a
sed -i '773,781d' a
sed -i '758,760d' a
sed -i '749,753d' a
sed -i '718,737d' a
sed -i '711,714d' a
sed -i '709d' a
sed -i '699d' a
sed -i '684d' a
sed -i '626,632d' a
sed -i '614,620d' a
sed -i '606d' a
sed -i '602d' a
sed -i '599d' a
sed -i '588d' a
sed -i '572,577d' a
sed -i '550,551d' a
sed -i '542,546d' a
sed -i '533,537d' a
sed -i '525,529d' a
sed -i '517,521d' a
sed -i '492,500d' a
sed -i '385d' a
sed -i '365,383d' a
sed -i '355,359d' a
sed -i '349,351d' a
sed -i '337,345d' a
sed -i '327d' a
sed -i '324,325d' a
sed -i '311,313d' a
sed -i '286,309d' a
sed -i '271,277d' a
sed -i '236,238d' a
sed -i '232d' a
sed -i '221,229d' a
sed -i '201,204d' a
sed -i '194d' a
sed -i '184d' a
sed -i '180d' a
sed -i '166,172d' a
sed -i '164d' a
sed -i '158d' a
sed -i '149,152d' a
sed -i '119,138d' a
sed -i '117d' a
sed -i '76,81d' a
sed -i '74d' a
sed -i '69,71d' a
sed -i '59,63d' a
sed -i '62d' a
sed -i '57d' a
sed -i '45,49d' a
sed -i '43d' a
sed -i '35,37d' a
sed -i '28,31d' a
sed -i '26d' a
sed -i '21,23d' a
sed -i '19d' a
sed -i '3d' a

sed -i '100s/    //' a
sed -i '120s/    //' a
sed -i '187d' a

sed -i '545s/thread/thread or periodic_thread/' a

sed -i '536 i\\n            if self.on_periodic:' a
sed -i '538 i\                periodic_thread = threading.Thread(target=self._periodic, args=())' a
sed -i '539 i\                periodic_thread.setDaemon(True)' a
sed -i '540 i\                periodic_thread.start()' a

sed -i '525 i\        periodic_thread = None' a

sed -i '516 i\\n    def _periodic(self):' a
sed -i '518 i\        while True:' a
sed -i '519 i\            time.sleep(0.1)' a
sed -i '520 i\            if not self.keep_running:' a
sed -i '521 i\                return' a
sed -i '522 i\\n            self._callback(self.on_periodic)' a

sed -i '497 i\        self.on_periodic = on_periodic' a
sed -i '490s/keep_running/on_periodic=None, keep_running/' a
sed -i '490s/get_mask_key/\n                 get_mask_key/' a

sed -i '111s/OPCODE_PING/ OPCODE_CLOSE, OPCODE_PING/' a
sed -i '110s/ OPCODE_CLOSE,//' a
sed -i '110s/(/(\n        /' a
sed -i '112s/)/\n    )/' a
sed -i '112s/         O/O/' a

sed -i 's/    /\t/g' a
sed -i 's/\t/  /g' a
sed -i '295s/"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"/MAGIC_STRING/' a

sed -i '351s/opcode,/_,/' a

sed -i '145s/opcode/opcode, mask=1/' a
sed -i '148s/opcode, 1/opcode, mask/' a

sed '53,470d' websocket_server.py | sed '1,50d' | sed '13d' > b
sed '470,$d' websocket_server.py | sed '1,52d' >> b
sed -i '68d' b
sed -i '22d' b
sed -i '385d' b
sed -i '382d' b
sed -i '367d' b
sed -i '361d' b
sed -i '356d' b
sed -i -E '344s/\s+#.*$//' b
sed -i '337,342d' b
sed -i '330d' b
sed -i '315,321d' b
sed -i -E '257s/\s+#.*$//' b
sed -i -E '234s/\s+#.*$//' b
sed -i '210,212d' b
sed -i '202,204d' b
sed -i '193,195d' b
sed -i '184,186d' b
sed -i '177,179d' b
sed -i -E '90s/\s+#.*$//' b
sed -i '68,88d' b
sed -i '379d' b
sed -i '190d' b
sed -i '188d' b

sed -i 's/CLOSE_STATUS_NORMAL/STATUS_NORMAL/g' b
sed -i '22s/, threaded=False//' b
sed -i '86s/, threaded//' b
sed -i -E '96,98s/^    //g' b
sed -i '90,95d' b
sed -i '82d' b
sed -i 's/sha1(/hashlib.sha1(/g' b
sed -i 's/b64encode(/base64.b64encode(/g' b

sed -i 's/OPCODE_CONTINUATION/OPCODE_CONT/g' b
sed -i 's/OPCODE_CLOSE_CONN/OPCODE_CLOSE/g' b
sed -i 's/OPCODE_/ABNF.OPCODE_/g' b

sed -i 's/PAYLOAD_LEN/ABNF.LENGTH_7/g' b
sed -i 's/PAYLOAD_LEN_EXT16/ABNF.LENGTH_16/g' b
sed -i 's/PAYLOAD_LEN_EXT64/ABNF.LENGTH_63/g' b

sed -i 's/StreamRequestHandler/SimpleHTTPRequestHandler/g' b

sed -i '1 i\FIN    = 0x80' b
sed -i '2 i\OPCODE = 0x0f' b
sed -i '3 i\MASKED = 0x80' b

sed -i '92d' b
sed -i '188,192d' b

sed -i '74s/, key=None, cert=None//' b
sed -i '79,81d' b

sed -i 's/    /\t/g' b
sed -i 's/\t/  /g' b

sed -i '74s/):/,\n         on_accept=None, on_close=None, on_message=None, on_periodic=None):/' b
sed -i '81 i\    self.on_accept = on_accept\n    self.on_close = on_close\n    self.on_message = on_message\n    self.on_periodic = on_periodic\n' b

sed -i '70,184s/_unicast/send_message/g' b
sed -i '70,184s/_multicast/send_message_to_all/g' b
sed -i '70,184s/_deny_new_connections/deny_new_connections/g' b
sed -i '70,184s/_allow_new_connections/allow_new_connections/g' b
sed -i '70,184s/_shutdown_gracefully/shutdown_gracefully/g' b
sed -i '70,184s/_shutdown_abruptly/shutdown_abruptly/g' b
sed -i '70,184s/_disconnect_clients_gracefully/disconnect_clients_gracefully/g' b
sed -i '70,184s/_disconnect_clients_abruptly/disconnect_clients_abruptly/g' b

sed -i '186 i\  def _callback(self, callback, *args):' b
sed -i '187 i\    if callback:' b
sed -i '188 i\      try:' b
sed -i '189 i\        callback(*args)' b
sed -i '190 i\      except Exception, e:' b
sed -i '191 i\        logger.error(e)\n' b

sed -i '133 i\    self._callback(self.on_close, client)' b
sed -i '132d' b

sed -i '129 i\    self._callback(self.on_accept, client)' b
sed -i '128d' b

sed -i '106 i\    self._callback(self.on_message, self.handler_to_client(handler), msg)' b
sed -i '105d' b
sed -i '70s/TCPServer, API/HTTPServer/' b
sed -i '23,68d' b
sed -i '31s/TCPServer/HTTPServer/' b
sed -i '45s/_run_forever/run_forever/' b

sed -i '47 i\    periodic_thread = None' b
sed -i '46d' b

sed -i '50 i\\n      if self.on_periodic:' b
sed -i '52 i\        periodic_thread = threading.Thread(target=self._periodic, args=())' b
sed -i '53 i\        periodic_thread.setDaemon(True)' b
sed -i '54 i\        periodic_thread.start()\n' b
sed -i '49d' b

sed -i '43 i\    self.keep_alive = keep_alive' b
sed -i '29s/):/,\n         keep_alive=True):/' b

sed -i '62 i\      if periodic_thread:' b
sed -i '63 i\        self.keep_alive = False' b

sed -i '59 i\      if periodic_thread:' b
sed -i '60 i\        self.keep_alive = False' b

sed -i '151 i\  def _periodic(self):' b
sed -i '152 i\    while True:' b
sed -i '153 i\      time.sleep(0.1)' b
sed -i '154 i\      if not self.keep_alive:' b
sed -i '155 i\        return\n' b

sed -i '157 i\      self._callback(self.on_periodic, self)\n' b

sed -i '188 i\  def read_bytes(self, bufsize):' b
sed -i '189 i\    shortage = bufsize - sum(len(x) for x in self._recv_buffer)' b
sed -i '190 i\    while shortage > 0:' b
sed -i '191 i\      bytes = self.rfile.read(shortage)' b
sed -i '192 i\      self._recv_buffer.append(bytes)' b
sed -i '193 i\      shortage -= len(bytes)' b
sed -i '194 i\    unified = self._recv_buffer[:]' b
sed -i '195 i\    if shortage == 0:' b
sed -i '196 i\      self._recv_buffer = []' b
sed -i "197 i\      return unified" b
sed -i '198 i\    else:' b
sed -i '199 i\      self._recv_buffer = unified[bufsize:]' b
sed -i "200 i\      return unified[:bufsize]" b
sed -i '186,187d' b

sed -i '178 i\    self._recv_buffer = []' b

sed -i '244,246s/self.rfile.read/self.read_bytes/g' b

sed -i '180 i\  def do_GET(self):' b
sed -i '181 i\    self.handle_method("GET")\n' b

sed -i '183 i\  def do_HEAD(self):' b
sed -i '184 i\    self.handle_method("HEAD")\n' b

sed -i '186 i\  def do_POST(self):' b
sed -i '187 i\    self.handle_method("POST")\n' b

sed -i '189 i\  def do_PUT(self):' b
sed -i '190 i\    self.handle_method("PUT")\n' b

sed -i '192 i\  def do_DELETE(self):' b
sed -i '193 i\    self.handle_method("DELETE")\n' b

sed -i '195 i\  def handle_method(self, method):' b
sed -i '196d' b

sed -i '326,335d' b

sed -i '326 i\    return self.headers' b

sed -i '332s/upgrade/Upgrade/' b
sed -i '338s/sec-websocket-key/Sec-WebSocket-Key/' b

sed -i '362s/GUID/MAGIC_STRING/' b
sed -i '362s/hash /_hash /' b
sed -i '363s/hash/_hash/' b
sed -i '361d' b

sed -i -E '196,200s/^  /    /g' b
sed -i '201 i\\n      self.send_response(403)' b
sed -i '203 i\      self.send_header("Content-type", "application/json")' b
sed -i '204 i\      self.end_headers()' b
sed -i '205 i\      self.wfile.write(json_encode({"error":"No route"}))' b
sed -i '206 i\      return\n' b

sed -i "208 i\    if re.match(r'^/[?#&]*$', self.path):" b
sed -i '209 i\      self.send_response(200)' b
sed -i '210 i\      self.send_header("Content-type", "application/json")' b
sed -i '211 i\      self.end_headers()' b
sed -i '212 i\      self.wfile.write(json_encode({"message":"Hi there"}))' b

sed -i "196 i\    if re.match(r'^/polling', self.path) and method == 'GET':" b

sed -i '28s/loglevel=logging.WARNING/on_accept=None/' b
sed -i '29s/on_accept=None, //' b
sed -i '29s/on_periodic=None,/on_periodic=None, keep_alive=True):/' b
sed -i '30,31d' b

sed -i -E '4s/bytes.*$/""/' b
sed -i '290 i\      raise Exception("CLOSE status must be between 1000 and 1015, got %d" % status)' b
sed -i '289d' b

sed -i '24s/ThreadingMixIn, HTTPServer/HTTPServer, object/' b
sed -i '55s/super()/super(WebsocketServer, self)/' b

sed '48,$d' websocket.py | sed '30d' | sed '1,22d' | sed 's|    |\t|g' | sed 's|\t|  |g' > c
sed '12,$d' websocket_server.py | sed '1,9d' >> c
cat >> c <<EOF
import json, re
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer

EOF

sed '16,$d' a >> c
sed '6,$d' b >> c
sed '102,$d' a | sed '92,95d' | sed '16,88d' | sed '1,15d' >> c
sed '30,$d' a | sed '17,25d' | sed '1,15d' >> c
cat >> c <<EOF
webp_config = {
  "port":8900,
  "stream":"wss://streaming.forexpros.com/echo/783/8t4hwg0n/websocket",
  "uuid":"255768773",
  "tzID":"110",
  "symbols": [
    {
      "name":"RMU24",
      "pid":"8911"
    },
    {
      "name":"KCU24",
      "pid":"8832"
    }
  ],
  "period": 10,
  "liffe": {
    "name": "London",
    "open":"15:00",
    "close":"23:30"
  },
  "ice": {
    "name": "New York",
    "open":"15:15",
    "close":"00:30"
  }
}

symbol_trans = {}
m_last_changed = {}
heartbeat_recv = 0;

mutex_mqtt = threading.Lock()
mqtt = []

EOF
sed '24,$d' b | sed '1,5d' >> c
cat >> c <<EOF
def json_encode(o):
  return json.dumps(o, ensure_ascii=False)

def json_decode(s):
  try:
    return json.loads(s)
  except:
    return None

def to_number(s):
  try:
    return float(s)
  except:
    return 0
EOF

sed '189,$d' a | sed '96,100d' | sed '89,92d' | sed '26,28d' | sed '1,16d' >> c
sed '1,23d' b >> c
sed '1,187d' a >> c

sed -i '33 i\MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"' c

cat >> c <<EOF

def on_investing_periodic(ws):
  global heartbeat_recv
  sec = int(time.time())
  if sec - heartbeat_recv >= 5:
    heartbeat_recv = sec;
    s = json_encode([json_encode({'_event':'heartbeat','data':'h'})])
    ws.send(s)

def on_investing_data(ws, message):
  global symbol_trans, m_last_changed, heartbeat_recv, mqtt
  if message == "o":
    ev = {
      "_event":"bulk-subscribe",
      "tzID":webp_config["tzID"]
    }
    s = ""
    for it in webp_config["symbols"]:
      symbol_trans[it['pid']] = it['name']
      m_last_changed[it['pid']] = 0
      if len(s) > 0:
        s += "%%"
      s += "isOpenPair-%s:" % it["pid"]
      s += "%spid-%s:" % ('%%', it["pid"])
      s += "%spidExt-%s:" % ('%%', it["pid"])

    ev["message"] = s

    a = [json_encode(ev)]
    ws.send(json_encode(a))
    ws.send(json_encode([json_encode({"_event":"UID","UID":webp_config["uuid"]})]))
    return

  if message[0] != 'a':
    return

  if 'heartbeat' in message:
    heartbeat_recv = int(time.time())
    return

  obj = json_decode(message[1:])

  if not isinstance(obj, list) or len(obj) == 0 or not isinstance(obj[0], (unicode,str)):
    return

  raw = obj[0].decode('string_escape')
  if '::{' in raw:
    raw = raw[raw.index('::{') + 2:]
    raw = raw[:-2]

  o = json_decode(raw)

  if not o:
    return

  if 'last_numeric' not in o and 'last' not in o or 'pid' not in o \
    or 'timestamp' not in o:
    return

  last = o['last_numeric'] if 'last_numeric' in o else to_number(o['last'])
  if last <= 0:
    return

  if o['pid'] not in symbol_trans:
    return

  if m_last_changed[o['pid']] != last:
    m_last_changed[o['pid']] = last
    sym = {
      'name':symbol_trans[o['pid']],
      'last':last,
      'timestamp':o['timestamp']
    }
    with mutex_mqtt:
      mqtt.append(sym)

def start_investing(cfg):
  try:
    ws = WebSocketApp(
      cfg["stream"],
      on_message = on_investing_data,
      on_periodic = on_investing_periodic
    )
    ws.run_forever()
  except KeyboardInterrupt:
    pass

def on_open(ws):
  print('#%d connected' % ws['id'])
  ws['handler'].send_message('Em giấu mùa hè sau cánh cửa')

def on_data(ws, message):
  print('#%d send %s' % (ws['id'], message))

def on_periodic(srv):
  global mqtt
  with mutex_mqtt:
    if len(mqtt) > 0:
      s = mqtt.pop(0)
      print('Queue -> ', s)

if __name__ == '__main__':
  enableTrace(True)
  investing_thread = None
  try:
    keep_running = True

    investing_thread = threading.Thread(target=start_investing, args=(webp_config,))
    investing_thread.setDaemon(True)
    investing_thread.start()

    server = WebsocketServer(host='127.0.0.1', port=webp_config["port"],
      on_accept=on_open, on_message=on_data, on_periodic=on_periodic)

    server.run_forever()
  except KeyboardInterrupt:
    if investing_thread:
      keep_running = False
EOF

cat > d.py <<EOF
#!/usr/bin/env python
# coding: utf-8

EOF

cat c >> d.py

sed -i '614,619d' d.py
sed -i '865d' d.py
sed -i "632 i\      'Server: Alpine\\\r\\\n'        \\\\" d.py

sed -i '607s/header + //' d.py

sed -i '605 i\    frame = ABNF.create_frame(message, opcode, 0)' d.py
sed -i '606 i\    payload = frame.format()' d.py
sed -i '584,604d' d.py

sed -i '450 i\    self._frame_header = None' d.py
sed -i '451 i\    self._frame_length = None' d.py
sed -i '452 i\    self._frame_mask = None' d.py
sed -i '453 i\    self._cont_data = None' d.py

sed -i '569s/payload/message/' d.py
sed -i '570s/(payload/(message/' d.py
sed -i '576s/header + //' d.py
sed -i '575 i\    frame = ABNF.create_frame(message, ABNF.OPCODE_CLOSE, 0)' d.py
sed -i '575 i\    payload = frame.format()' d.py
sed -i '573,574d' d.py

sed -i '605s/return/return False/' d.py
sed -i '612 i\    return True' d.py

sed -i '610 i\    if not self.handshake_done:' d.py
sed -i '611 i\      return False\n' d.py

sed '480,$d' a | sed '408,465d' | sed '1,353d' > e
cat >> e <<EOF
  def _recv(self, bufsize):
    try:
      bytes = self.rfile.read(bufsize)
    except (struct.error, TypeError) as e:
      if self.keep_alive:
        raise WebSocketException("Websocket read aborted while listening")
      else:
        logger.info("recv aborted after closed connection")
        pass

    if not bytes:
      raise WebSocketConnectionClosedException()
    return bytes
EOF

sed -i '22s/self.pong(/return (frame.opcode,/' e
sed -i '21s/ == / in (/' e
sed -i '21s/:/,ABNF.OPCODE_PONG):/' e
sed -i '19d' e

sed -i '4s/frame:/frame or frame.opcode not in (ABNF.OPCODE_TEXT,\n        ABNF.OPCODE_BINARY, ABNF.OPCODE_CONT, ABNF.OPCODE_CLOSE,\n         ABNF.OPCODE_PING,ABNF.OPCODE_PONG):/' e

# sed -i '3 i\      if not self.keep_alive:' e
# sed -i '4 i\        return\n' e

sed -i -E '535,540s/_$/_(self, data)/' d.py
sed -i '535,540s/opcode_handler = //' d.py
sed -i '545,556d' d.py
sed -i '525,528d' d.py
sed -i '505,519d' d.py

sed -i '505 i\    opcode, data = self.recv_data()' d.py
#sed -i '506,520d' d.py

sed '606,$d' d.py > f
cat e >> f
sed '1,604d' d.py >> f
mv f d.py
