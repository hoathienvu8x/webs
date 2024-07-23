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
