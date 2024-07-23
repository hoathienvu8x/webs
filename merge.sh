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
sed -i 's/b64encode(/base64.b64encode/g' b

sed -i 's/OPCODE_CONTINUATION/OPCODE_CONT/g' b
sed -i 's/OPCODE_CLOSE_CONN/OPCODE_CLOSE/g' b
sed -i 's/OPCODE_/ABNF.OPCODE_/g' b

sed -i 's/PAYLOAD_LEN/LENGTH_7/g' b
sed -i 's/PAYLOAD_LEN_EXT16/LENGTH_16/g' b
sed -i 's/PAYLOAD_LEN_EXT64/LENGTH_63/g' b

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

sed -i '186 i\  def _calback(self, callback, *args):' b
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
sed -i '191 i\      bytes = elf.rfile.read(shortage)' b
sed -i '192 i\      self._recv_buffer.append(bytes)' b
sed -i '193 i\      shortage -= len(bytes)' b
sed -i '194 i\    unified = "".join(self._recv_buffer)' b
sed -i '195 i\    if shortage == 0:' b
sed -i '196 i\      self._recv_buffer = []' b
sed -i "197 i\      return bytes(unified, 'utf-8')" b
sed -i '198 i\    else:' b
sed -i '199 i\      self._recv_buffer = [unified[bufsize:]]' b
sed -i "200 i\      return bytes(unified[:bufsize], 'utf-8')" b
sed -i '186,187d' b

sed -i '178 i\    self._recv_buffer = []' b

sed -i '244,246s/self.rfile.read/self.read_bytes/g' b
