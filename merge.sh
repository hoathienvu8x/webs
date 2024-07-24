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
  global symbol_trans, m_last_changed, heartbeat_recv, mqtt, all_symbols
  if message == "o":
    ev = {
      "_event":"bulk-subscribe",
      "tzID":webp_config["tzID"]
    }
    s = ""
    for it in webp_config["symbols"]:
      symbol_trans[it['pid']] = it['name']
      m_last_changed[it['pid']] = 0
      if it['name'] not in all_symbols:
        all_symbols.append(it['name'])
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
      'symbol':symbol_trans[o['pid']],
      'price':last,
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

def save_quote_data(obj):
  print(json_encode(obj))

def on_open(ws):
  print('#%d connected' % ws['id'])
  ws['handler'].send_message('Em giấu mùa hè sau cánh cửa')

def on_data(ws, message):
  global all_symbols, mdb, m_subcribed, webp_config
  # print('#%d send %s' % (ws['id'], message))
  obj = json_decode(message)
  if not isinstance(obj, dict):
    return

  if '_event' not in obj or not isinstance(obj['_event'], (str, unicode)):
    return

  if obj['_event'] == 'heartbeat':
    ws['handler'].send_message(json_encode({"heartbeat":"h"}))
    return

  if obj['_event'] == 'subcribed':
    if 'symbol' not in obj or not isinstance(obj['symbol'], (str, unicode)):
      return

    if not obj['symbol']:
      return

    _period = 5
    if 'period' in obj and isinstance(obj['period'], (float, int)):
      _period = int(obj['period'])

    if _period not in (5,10,15,30,60):
      _period = 5

    if obj['symbol'] not in all_symbols:
      return

    if obj['symbol'] not in m_subcribed:
      m_subcribed[obj['symbol']] = []

    found = False
    for c in m_subcribed[obj['symbol']]:
      if c['handler'] == ws['handler']:
        found = True
        break

    if not found:
      m_subcribed[obj['symbol']].append(ws)

    p = {
      'name':obj['symbol'],
      'contract':'',
      'exchange': webp_config["liffe"]["name"] if obj['symbol'][0:2] == 'RM' else webp_config["ice"]["name"],
      'open': webp_config["liffe"]["open"] if obj['symbol'][0:2] == 'RM' else webp_config["ice"]["open"],
      'close':webp_config["liffe"]["close"] if obj['symbol'][0:2] == 'RM' else webp_config["ice"]["close"],
      'ticks':[]
    }

    ws['handler'].send_message(json_encode(p))

    return

  if obj['_event'] == 'tick':
    if 'data' not in obj or not isinstance(obj['data'], list):
      return

    if len(obj['data']) == 0:
      return

    _commit = 0
    for it in obj['data']:
      if not isinstance(it, dict):
        continue

      if 'symbol' not in it or 'price' not in it or 'timestamp' not in it:
        continue

      if not isinstance(it['symbol'], (str, unicode)):
        continue

      if not isinstance(it['price'], (float, int)) or it['price'] <= 0:
        continue

      if not isinstance(it['timestamp'], int) or it['timestamp'] <= 0:
        continue

      _symbol = it['symbol']
      if _symbol not in all_symbols:
        continue

      _price = float(it['price'])
      _timestamp = int(it['timestamp'])
      _volume = 0
      if 'volume' in it and isintance(it['volume'],(int, float)) and it['volume'] > 0:
        _volume = int(it['volume'])

      if _symbol not in mdb:
        mdb[_symbol] = []

      mdb[_symbol].append({
        'price': _price,
        'volume':_volume,
        'timestamp':_timestamp
      })

      _commit += 1

      p = {
        '_event':'tick',
        'symbol':_symbol,
        'price':_price,
        'timestamp':_timestamp
      }

      if _volume > 0:
        p['volume'] = _volume

      if _symbol in m_subcribed:
        for c in m_subcribed[_symbol]:
          if c['handler'] == ws['handler']:
            continue

          c['handler'].send_message(json_encode(p))

    if _commit > 0:
      save_quote_data(mdb)

def on_close(ws):
  global m_subcribed
  for _symbol in m_subcribed:
    for c in m_subcribed[_symbol]:
      if c['handler'] == ws['handler']:
        m_subcribed[_symbol].remove(c)
        break

def on_periodic(srv):
  global mqtt, mdb, m_subcribed, all_symbols
  with mutex_mqtt:
    if len(mqtt) == 0:
      return
    it = mqtt.pop(0)
    if not isinstance(it, dict):
      return

    if 'symbol' not in it or 'price' not in it or 'timestamp' not in it:
      return

    if not isinstance(it['symbol'], (str, unicode)):
      return

    if not isinstance(it['price'], (float, int)) or it['price'] <= 0:
      return

    if not isinstance(it['timestamp'], int) or it['timestamp'] <= 0:
      return

    _symbol = it['symbol']
    if _symbol not in all_symbols:
      return

    _price = float(it['price'])
    _timestamp = int(it['timestamp'])
    _volume = 0
    if 'volume' in it and isintance(it['volume'],(int, float)) and it['volume'] > 0:
      _volume = int(it['volume'])

    if _symbol not in mdb:
      mdb[_symbol] = []

    mdb[_symbol].append({
      'price': _price,
      'volume':_volume,
      'timestamp':_timestamp
    })

    p = {
      '_event':'tick',
      'symbol':_symbol,
      'price':_price,
      'timestamp':_timestamp
    }

    if _volume > 0:
      p['volume'] = _volume

    if _symbol in m_subcribed:
      for c in m_subcribed[_symbol]:
        c['handler'].send_message(json_encode(p))

    save_quote_data(mdb)

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

sed -i '138 i\def html_minify(html):' d.py
sed -i "139 i\  html = re.sub('[\\\r\\\n\\\t]',' ', html)" d.py
sed -i "140 i\  html = re.sub('\\\s{2,}',' ', html)" d.py
sed -i "141 i\  html = re.sub('/\\\*[^\\\*]+\\\*/','', html)" d.py
sed -i "142 i\  html = html.replace('> <','><')" d.py
sed -i '143 i\  return html\n' d.py

sed '493,$d' d.py > f
cat >> f <<EOF
      self.send_header("Content-type", "text/html")
      self.end_headers()
      html_tpl = '''
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>Trading analysis indicators</title>
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
    <meta name="theme-color" media="(prefers-color-scheme: light)" content="#164c34">
    <meta name="theme-color" media="(prefers-color-scheme: dark)" content="#0e2f20">
    <link rel="icon" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAABoVBMVEUWTDQVSzMUSzMUSzIRSDAORi0RSC8SSTEQRy4NRSwQRy8LQyp7mYzc5OHZ4t6rvrYJQik7aVTW4NvU3trQ29YzYk0GQCaasaf///8DPiRFcF06aFQGPyaUraLR3NcCPSNHcl87aVUNRS0EPiSTrKEHQCcxYUyovLOmu7KkubArXEYHQScKQykAOh+PqZ0MRCsKQyoANRoAMhcANhsVTDMLRCsbUDh0lIa9zMbU3tnM2NPo7esyYk3Y4d08aVUSSTAYTTXT3djj6efM2NLz9vRDbls4ZlEIQihmiXqFoZUTSjEAOR+VrqOht63X4NwMRSzBz8mkua8DPSMIQSi1xr6/zscEPiUTSjKNp5tTe2kAOyEAMxeMp5tCblo4ZlI9alb7/PuwwrqbsqjV39sBPCJJc2A2ZFAJQih1lYfa499ninr4+vkpW0UPRy5NdmS0xr7p7uz5+/r6+/r09vXk6uebs6hzk4X19/YiVT8aTzgqW0U6aFMsXUchVT4LRCqxw7vg5+QVTDRUfGoUSjIdUTp/nZD+/v6zxb0IQSc3ZVE/bFiQW5uEAAABRUlEQVQ4y82TVVcCYRRFGWAYB+zAbQ12YSu22IodmNiJhd1iK8av9kGexhmfua9nr7vOd+75DIaIG8FoFAwGwSjo6CazKFokKUq2StqILTomNi4+ITEpOcWqCdhTITYtHciQNYHMLFAc2UBOrpZDIS8flILCouKSUvMf2ewsE8srQKmsqq6plevUuqu+obGpuUV3g6u1jd/59eBWeWjv6AS6untAcfQCfapX9HuAgcGhYT3APgKjY2Jevg4g2MZhYjKcg9YG7xRMz8zqA/Y5YN63sAiKYwlYVgHyCrC6tr4ByuYWsC2qUvbvhGNg17cH+wcBVVCz/sOj4xNOz84vyi/h6try51I2783tXfDe9LD5CE/PgxrHlAJiwBLwvQAlBXqlfH17D0HIPaYHSMEPCHk+Bd1eW51fFd9O03/NF72yEFmf8QfznD3U4HEhEAAAAABJRU5ErkJggg==" />

    <link rel="icon" href="data:image/png;base64,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" />
    <style>
    @charset "UTF-8";
    *, *:before, *:after {
      box-sizing: border-box;
    }
    html,body,div,span,applet,object,iframe,h1,h2,h3,h4,h5,h6,p,blockquote,
    pre,a,abbr,acronym,address,big,cite,code,del,dfn,em,img,ins,kbd,q,s,samp,
    small,strike,strong,sub,sup,tt,var,b,u,i,center,dl,dt,dd,ol,ul,li,fieldset,
    form,label,legend,table,caption,tbody,tfoot,thead,tr,th,td,article,aside,
    canvas,details,embed,figure,figcaption,footer,header,hgroup,menu,nav,
    output,ruby,section,summary,time,mark,audio,video {
      margin: 0;
      padding: 0;
      border: 0;
      font-size: 100%;
      font: inherit;
      vertical-align: baseline
    }

    article,aside,details,figcaption,figure,footer,header,hgroup,menu,nav,section {
      display: block
    }

    body {
      line-height: 1
    }

    ol,ul {
      list-style: none
    }

    blockquote,q {
      quotes: none
    }

    blockquote:before,blockquote:after,q:before,q:after {
      content: '';
      content: none
    }

    table {
      border-collapse: collapse;
      border-spacing: 0
    }

    :root {
      --white: #fff;
      --black: #000;
      --bg: #f8f8f8;
      --grey: #999;
      --dark: #1a1a1a;
      --light: #e6e6e6;
      --wrapper: 1000px;
      --blue: #00b0ff;
    }

    body {
      background-color: var(--bg);
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      text-rendering: optimizeLegibility;
      font-family: "Source Sans Pro", sans-serif;
      font-weight: 400;
      background-image: url("https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/image.jpg");
      background-size: cover;
      background-repeat: none;
    }

    .wrapper {
      position: relative;
      left: 50%;
      width: var(--wrapper);
      height: 800px;
      transform: translate(-50%, 0);
    }

    .container {
      position: relative;
      top: 50%;
      left: 50%;
      width: 80%;
      height: 75%;
      background-color: var(--white);
      transform: translate(-50%, -50%);
    }
    .container .left {
      float: left;
      width: 37.6%;
      height: 100%;
      border: 1px solid var(--light);
      background-color: var(--white);
    }
    .container .left .top {
      position: relative;
      width: 100%;
      height: 96px;
      padding: 29px;
    }
    .container .left .top:after {
      position: absolute;
      bottom: 0;
      left: 50%;
      display: block;
      width: 80%;
      height: 1px;
      content: "";
      background-color: var(--light);
      transform: translate(-50%, 0);
    }
    .container .left input {
      float: left;
      width: 188px;
      height: 42px;
      padding: 0 15px;
      border: 1px solid var(--light);
      background-color: #eceff1;
      border-radius: 21px;
      font-family: "Source Sans Pro", sans-serif;
      font-weight: 400;
    }
    .container .left input:focus {
      outline: none;
    }
    .container .left a.search {
      display: block;
      float: left;
      width: 42px;
      height: 42px;
      margin-left: 10px;
      border: 1px solid var(--light);
      background-color: var(--blue);
      background-image: url("https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/name-type.png");
      background-repeat: no-repeat;
      background-position: top 12px left 14px;
      border-radius: 50%;
    }
    .container .left .people {
      margin-left: -1px;
      border-right: 1px solid var(--light);
      border-left: 1px solid var(--light);
      width: calc(100% + 2px);
    }
    .container .left .people .person {
      position: relative;
      width: 100%;
      padding: 12px 10% 16px;
      cursor: pointer;
      background-color: var(--white);
    }
    .container .left .people .person:after {
      position: absolute;
      bottom: 0;
      left: 50%;
      display: block;
      width: 80%;
      height: 1px;
      content: "";
      background-color: var(--light);
      transform: translate(-50%, 0);
    }
    .container .left .people .person img {
      float: left;
      width: 40px;
      height: 40px;
      margin-right: 12px;
      border-radius: 50%;
      -o-object-fit: cover;
         object-fit: cover;
    }
    .container .left .people .person .name {
      font-size: 14px;
      line-height: 22px;
      color: var(--dark);
      font-family: "Source Sans Pro", sans-serif;
      font-weight: 600;
    }
    .container .left .people .person .time {
      font-size: 14px;
      position: absolute;
      top: 16px;
      right: 10%;
      padding: 0 0 5px 5px;
      color: var(--grey);
      background-color: var(--white);
    }
    .container .left .people .person .preview {
      font-size: 14px;
      display: inline-block;
      overflow: hidden !important;
      width: 70%;
      white-space: nowrap;
      text-overflow: ellipsis;
      color: var(--grey);
    }
    .container .left .people .person.active, .container .left .people .person:hover {
      margin-top: -1px;
      margin-left: -1px;
      padding-top: 13px;
      border: 0;
      background-color: var(--blue);
      width: calc(100% + 2px);
      padding-left: calc(10% + 1px);
    }
    .container .left .people .person.active span, .container .left .people .person:hover span {
      color: var(--white);
      background: transparent;
    }
    .container .left .people .person.active:after, .container .left .people .person:hover:after {
      display: none;
    }
    .container .right {
      position: relative;
      float: left;
      width: 62.4%;
      height: 100%;
    }
    .container .right .top {
      width: 100%;
      height: 47px;
      padding: 15px 29px;
      background-color: #eceff1;
    }
    .container .right .top span {
      font-size: 15px;
      color: var(--grey);
    }
    .container .right .top span .name {
      color: var(--dark);
      font-family: "Source Sans Pro", sans-serif;
      font-weight: 600;
    }
    .container .right .chat {
      position: relative;
      display: none;
      overflow: hidden;
      padding: 0 35px 92px;
      border-width: 1px 1px 1px 0;
      border-style: solid;
      border-color: var(--light);
      height: calc(100% - 48px);
      justify-content: flex-end;
      flex-direction: column;
    }
    .container .right .chat.active-chat {
      display: block;
      display: flex;
    }
    .container .right .chat.active-chat .bubble {
      transition-timing-function: cubic-bezier(0.4, -0.04, 1, 1);
    }
    .container .right .chat.active-chat .bubble:nth-of-type(1) {
      -webkit-animation-duration: 0.15s;
              animation-duration: 0.15s;
    }
    .container .right .chat.active-chat .bubble:nth-of-type(2) {
      -webkit-animation-duration: 0.3s;
              animation-duration: 0.3s;
    }
    .container .right .chat.active-chat .bubble:nth-of-type(3) {
      -webkit-animation-duration: 0.45s;
              animation-duration: 0.45s;
    }
    .container .right .chat.active-chat .bubble:nth-of-type(4) {
      -webkit-animation-duration: 0.6s;
              animation-duration: 0.6s;
    }
    .container .right .chat.active-chat .bubble:nth-of-type(5) {
      -webkit-animation-duration: 0.75s;
              animation-duration: 0.75s;
    }
    .container .right .chat.active-chat .bubble:nth-of-type(6) {
      -webkit-animation-duration: 0.9s;
              animation-duration: 0.9s;
    }
    .container .right .chat.active-chat .bubble:nth-of-type(7) {
      -webkit-animation-duration: 1.05s;
              animation-duration: 1.05s;
    }
    .container .right .chat.active-chat .bubble:nth-of-type(8) {
      -webkit-animation-duration: 1.2s;
              animation-duration: 1.2s;
    }
    .container .right .chat.active-chat .bubble:nth-of-type(9) {
      -webkit-animation-duration: 1.35s;
              animation-duration: 1.35s;
    }
    .container .right .chat.active-chat .bubble:nth-of-type(10) {
      -webkit-animation-duration: 1.5s;
              animation-duration: 1.5s;
    }
    .container .right .write {
      position: absolute;
      bottom: 29px;
      left: 30px;
      height: 42px;
      padding-left: 8px;
      border: 1px solid var(--light);
      background-color: #eceff1;
      width: calc(100% - 58px);
      border-radius: 5px;
    }
    .container .right .write input {
      font-size: 16px;
      float: left;
      width: 347px;
      height: 40px;
      padding: 0 10px;
      color: var(--dark);
      border: 0;
      outline: none;
      background-color: #eceff1;
      font-family: "Source Sans Pro", sans-serif;
      font-weight: 400;
    }
    .container .right .write .write-link.attach:before {
      display: inline-block;
      float: left;
      width: 20px;
      height: 42px;
      content: "";
      background-image: url("https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/attachment.png");
      background-repeat: no-repeat;
      background-position: center;
    }
    .container .right .write .write-link.smiley:before {
      display: inline-block;
      float: left;
      width: 20px;
      height: 42px;
      content: "";
      background-image: url("https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/smiley.png");
      background-repeat: no-repeat;
      background-position: center;
    }
    .container .right .write .write-link.send:before {
      display: inline-block;
      float: left;
      width: 20px;
      height: 42px;
      margin-left: 11px;
      content: "";
      background-image: url("https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/send.png");
      background-repeat: no-repeat;
      background-position: center;
    }
    .container .right .bubble {
      font-size: 16px;
      position: relative;
      display: inline-block;
      clear: both;
      margin-bottom: 8px;
      padding: 13px 14px;
      vertical-align: top;
      border-radius: 5px;
    }
    .container .right .bubble:before {
      position: absolute;
      top: 19px;
      display: block;
      width: 8px;
      height: 6px;
      content: " ";
      transform: rotate(29deg) skew(-35deg);
    }
    .container .right .bubble.you {
      float: left;
      color: var(--white);
      background-color: var(--blue);
      align-self: flex-start;
      -webkit-animation-name: slideFromLeft;
              animation-name: slideFromLeft;
    }
    .container .right .bubble.you:before {
      left: -3px;
      background-color: var(--blue);
    }
    .container .right .bubble.me {
      float: right;
      color: var(--dark);
      background-color: #eceff1;
      align-self: flex-end;
      -webkit-animation-name: slideFromRight;
              animation-name: slideFromRight;
    }
    .container .right .bubble.me:before {
      right: -3px;
      background-color: #eceff1;
    }
    .container .right .conversation-start {
      position: relative;
      width: 100%;
      margin-bottom: 27px;
      text-align: center;
    }
    .container .right .conversation-start span {
      font-size: 14px;
      display: inline-block;
      color: var(--grey);
    }
    .container .right .conversation-start span:before, .container .right .conversation-start span:after {
      position: absolute;
      top: 10px;
      display: inline-block;
      width: 30%;
      height: 1px;
      content: "";
      background-color: var(--light);
    }
    .container .right .conversation-start span:before {
      left: 0;
    }
    .container .right .conversation-start span:after {
      right: 0;
    }

    @keyframes slideFromLeft {
      0% {
        margin-left: -200px;
        opacity: 0;
      }
      100% {
        margin-left: 0;
        opacity: 1;
      }
    }
    @-webkit-keyframes slideFromLeft {
      0% {
        margin-left: -200px;
        opacity: 0;
      }
      100% {
        margin-left: 0;
        opacity: 1;
      }
    }
    @keyframes slideFromRight {
      0% {
        margin-right: -200px;
        opacity: 0;
      }
      100% {
        margin-right: 0;
        opacity: 1;
      }
    }
    @-webkit-keyframes slideFromRight {
      0% {
        margin-right: -200px;
        opacity: 0;
      }
      100% {
        margin-right: 0;
        opacity: 1;
      }
    }
    </style>
  </head>
  <body>
    <div class="wrapper">
      <div class="container">
        <div class="left">
          <div class="top">
            <input type="text" placeholder="Search" />
            <a href="javascript:;" class="search"></a>
          </div>
          <ul class="people">
            <li class="person" data-chat="person1">
              <img src="https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/thomas.jpg" alt="" />
              <span class="name">Thomas Bangalter</span>
              <span class="time">2:09 PM</span>
              <span class="preview">I was wondering...</span>
            </li>
            <li class="person" data-chat="person2">
              <img src="https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/dog.png" alt="" />
              <span class="name">Dog Woofson</span>
              <span class="time">1:44 PM</span>
              <span class="preview">I've forgotten how it felt before</span>
            </li>
            <li class="person" data-chat="person3">
              <img src="https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/louis-ck.jpeg" alt="" />
              <span class="name">Louis CK</span>
              <span class="time">2:09 PM</span>
              <span class="preview">But we’re probably gonna need a new carpet.</span>
            </li>
            <li class="person" data-chat="person4">
              <img src="https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/bo-jackson.jpg" alt="" />
              <span class="name">Bo Jackson</span>
              <span class="time">2:09 PM</span>
              <span class="preview">It’s not that bad...</span>
            </li>
            <li class="person" data-chat="person5">
              <img src="https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/michael-jordan.jpg" alt="" />
              <span class="name">Michael Jordan</span>
              <span class="time">2:09 PM</span>
              <span class="preview">Wasup for the third time like is
                you blind bitch</span>
            </li>
            <li class="person" data-chat="person6">
              <img src="https://s3-us-west-2.amazonaws.com/s.cdpn.io/382994/drake.jpg" alt="" />
              <span class="name">Drake</span>
              <span class="time">2:09 PM</span>
              <span class="preview">howdoyoudoaspace</span>
            </li>
          </ul>
        </div>
        <div class="right">
          <div class="top"><span>To: <span class="name">Dog Woofson</span></span></div>
          <div class="chat" data-chat="person1">
            <div class="conversation-start">
              <span>Today, 6:48 AM</span>
            </div>
            <div class="bubble you">
              Hello,
            </div>
            <div class="bubble you">
              it's me.
            </div>
            <div class="bubble you">
              I was wondering...
            </div>
          </div>
          <div class="chat" data-chat="person2">
            <div class="conversation-start">
              <span>Today, 5:38 PM</span>
            </div>
            <div class="bubble you">
              Hello, can you hear me?
            </div>
            <div class="bubble you">
              I'm in California dreaming
            </div>
            <div class="bubble me">
              ... about who we used to be.
            </div>
            <div class="bubble me">
              Are you serious?
            </div>
            <div class="bubble you">
              When we were younger and free...
            </div>
            <div class="bubble you">
              I've forgotten how it felt before
            </div>
          </div>
          <div class="chat" data-chat="person3">
            <div class="conversation-start">
              <span>Today, 3:38 AM</span>
            </div>
            <div class="bubble you">
              Hey human!
            </div>
            <div class="bubble you">
              Umm... Someone took a shit in the hallway.
            </div>
            <div class="bubble me">
              ... what.
            </div>
            <div class="bubble me">
              Are you serious?
            </div>
            <div class="bubble you">
              I mean...
            </div>
            <div class="bubble you">
              It’s not that bad...
            </div>
            <div class="bubble you">
              But we’re probably gonna need a new carpet.
            </div>
          </div>
          <div class="chat" data-chat="person4">
            <div class="conversation-start">
              <span>Yesterday, 4:20 PM</span>
            </div>
            <div class="bubble me">
              Hey human!
            </div>
            <div class="bubble me">
              Umm... Someone took a shit in the hallway.
            </div>
            <div class="bubble you">
              ... what.
            </div>
            <div class="bubble you">
              Are you serious?
            </div>
            <div class="bubble me">
              I mean...
            </div>
            <div class="bubble me">
              It’s not that bad...
            </div>
          </div>
          <div class="chat" data-chat="person5">
            <div class="conversation-start">
              <span>Today, 6:28 AM</span>
            </div>
            <div class="bubble you">
              Wasup
            </div>
            <div class="bubble you">
              Wasup
            </div>
            <div class="bubble you">
              Wasup for the third time like is <br />you blind bitch
            </div>

          </div>
          <div class="chat" data-chat="person6">
            <div class="conversation-start">
              <span>Monday, 1:27 PM</span>
            </div>
            <div class="bubble you">
              So, how's your new phone?
            </div>
            <div class="bubble you">
              You finally have a smartphone :D
            </div>
            <div class="bubble me">
              Drake?
            </div>
            <div class="bubble me">
              Why aren't you answering?
            </div>
            <div class="bubble you">
              howdoyoudoaspace
            </div>
          </div>
          <div class="write">
            <a href="javascript:;" class="write-link attach"></a>
            <input type="text" />
            <a href="javascript:;" class="write-link smiley"></a>
            <a href="javascript:;" class="write-link send"></a>
          </div>
        </div>
      </div>
    </div>
    <script>
      let timeseries = [];
      let Indicators = {
        sma: function(data, period) {
          let output = [];
          let scale = 1.0 / period;
          let total = 0;
          let i;
          for (i = 0; i < period; i++) {
            total += data[i];
          }
          output.push(total * scale);
          for (i = period; i < data.length; i++) {
            total += data[i] - data[i - period];
            output.push(total * scale);
          }
          return output;
        },
        ema: function(data, period) {
          let output = [];
          let p = 2.0 / (period + 1);
          let val = 0;
          let i;
          for (i = 0; i < period; i++) {
            val += data[i];
          }
          val /= period;
          output.push(val);
          output.push(((data[period] - val) * p) + val);
          let j = 1;
          for (i = period; i < data.length; i++) {
            let tmp = ((data[i] - output[j]) * p) + output[j];
            j += 1;
            output.push(tmp);
          }
          return output;
        },
        psar : function(high, low, af, maxaf) {
          let output = [];
          let accel_step = 1.0 / af;
          let accel_max = 1.0 / maxaf;
          let lng = 0;
          if (high[0] + low[0] <= high[1] + low[1]) {
            lng = 1;
          }
          let sar = lng ? low[0] : high[0];
          let extreme = lng ? high[0] : low[0];
          let accel = accel_step;
          let i;
          for (i = 0; i < high.length; i++) {
            sar = (extreme - sar) * accel + sar;
            if (lng) {
              if (i >= 2 && sar > low[i - 2]) {
                sar = low[i - 2];
              }
              if (sar > low[i - 1]) {
                sar = low[i - 1];
              }
              if (accel < accel_max && high[i] > extreme) {
                accel += accel_step;
                if (accel > accel_max) {
                  accel = accel_max;
                }
              }
              if (high[i] > extreme) {
                extreme = high[i];
              }
            } else {
              if (i >= 2 && sar < high[i - 2]) {
                sar = high[i - 2];
              }
              if (sar < high[i - 1]) {
                sar = high[i - 1];
              }
              if (accel < accel_max && low[i] < extreme) {
                accel += accel_step;
                if (accel > accel_max) {
                  accel = accel_max;
                }
              }
              if (low[i] < extreme) {
                extreme = low[i];
              }
            }
            if ((lng && low[i] < sar) || (!lng && high[i] > sar)) {
              accel = accel_step;
              sar = extreme;
              lng = !lng;
              extreme = lng ? high[i] : low[i];
            }
            output.push(sar);
          }
          return output;
        }
      };
      document.addEventListener('DOMContentLoaded', function() {
        document.querySelector(".chat[data-chat=person2]").classList.add("active-chat");
        document.querySelector(".person[data-chat=person2]").classList.add("active");

        let friends = {
          list: document.querySelector("ul.people"),
          all: document.querySelectorAll(".left .person"),
          name: ""
        },
        chat = {
          container: document.querySelector(".container .right"),
          current: null,
          person: null,
          name: document.querySelector(".container .right .top .name")
        };
        function setAciveChat(f) {
          friends.list.querySelector(".active").classList.remove("active");
          f.classList.add("active");
          chat.current = chat.container.querySelector(".active-chat");
          chat.person = f.getAttribute("data-chat");
          chat.current.classList.remove("active-chat");
          chat.container
            .querySelector('[data-chat="' + chat.person + '"]')
            .classList.add("active-chat");
          friends.name = f.querySelector(".name").innerText;
          chat.name.innerHTML = friends.name;
        }
        friends.all.forEach((f) => {
          f.addEventListener("mousedown", () => {
            f.classList.contains("active") || setAciveChat(f);
          });
        });
      });
    </script>
  </body>
</html>
'''
      self.wfile.write(html_minify(html_tpl))
EOF

sed '613,$d' d.py | sed '1,495d' >> f
cat e >> f
sed '1,611d' d.py >> f
mv f d.py


sed -i '101 i\all_symbols = []\nm_subcribed = {}\nmdb = {}' d.py
