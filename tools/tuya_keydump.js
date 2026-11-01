/*
 * tuya_keydump.js  (v2, lean) — extract Tuya BLE local_key[:6] via Frida 17.
 *
 *   login_key   = MD5( local_key[:6] )          -> MD5 input of length 6
 *   session_key = MD5( local_key[:6] + srand )  -> MD5 input of length 22
 *
 * v2 changes: only log MD5 (SHA-1/SHA-256 flood removed, which was choking the
 * UI), and fix the Frida-17 native export API.
 *
 * Run (output to a file to avoid USB log overhead; replace the package name
 * if your app is Smart Life or a white-label build):
 *   frida -U -f com.tuya.smart -l tuya_keydump.js -o fridalog.txt
 * then open the scale in the app and step on it. Afterwards:
 *   python find_local_key.py fridalog.txt
 */
'use strict';

function b2hex(arr) {
  var s = '';
  for (var i = 0; i < arr.length; i++) { var v = (arr[i] & 0xff).toString(16); s += (v.length < 2 ? '0' : '') + v; }
  return s;
}
function b2ascii(arr) {
  var s = '';
  for (var i = 0; i < arr.length; i++) { var c = arr[i] & 0xff; s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.'; }
  return s;
}

Java.perform(function () {
  console.log('[*] tuya_keydump v2 loaded — now connect to the scale and step on it.');

  // --- MD5 only. A length-6 input is local_key[:6]; length-22 is local_key[:6]+srand.
  function logMD5(algo, arr, len) {
    if (algo !== 'MD5') return;
    if (len <= 0 || len > 40) return;
    console.log('[MD5 in] len=' + len + '  ascii="' + b2ascii(arr) + '"  hex=' + b2hex(arr));
  }
  try {
    var MD = Java.use('java.security.MessageDigest');
    MD.digest.overload('[B').implementation = function (input) {
      try { logMD5(this.getAlgorithm(), input, input.length); } catch (e) {}
      return this.digest(input);
    };
    MD.update.overload('[B').implementation = function (input) {
      try { logMD5(this.getAlgorithm(), input, input.length); } catch (e) {}
      return this.update(input);
    };
    MD.update.overload('[B', 'int', 'int').implementation = function (input, off, len) {
      try {
        if (this.getAlgorithm() === 'MD5' && len > 0 && len <= 40) {
          var slice = []; for (var i = 0; i < len; i++) slice.push(input[off + i]);
          logMD5('MD5', slice, len);
        }
      } catch (e) {}
      return this.update(input, off, len);
    };
    console.log('[+] hooked MessageDigest (MD5 filter)');
  } catch (e) { console.log('[-] MessageDigest hook failed: ' + e); }

  // --- AES keys (login_key / session_key appear here as 16 bytes).
  try {
    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
    SKS.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
      try { if ((algo + '').toUpperCase().indexOf('AES') >= 0) console.log('[AES key] len=' + key.length + '  hex=' + b2hex(key)); } catch (e) {}
      return this.$init(key, algo);
    };
    console.log('[+] hooked SecretKeySpec');
  } catch (e) { console.log('[-] SecretKeySpec hook failed: ' + e); }

  // --- AES IVs (confirms CBC + gives the IV for that frame).
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation =
      function (mode, key, spec) {
        try {
          var t = this.getAlgorithm();
          if (t && t.toUpperCase().indexOf('AES') >= 0) {
            var iv = '';
            try { iv = '  iv=' + b2hex(Java.cast(spec, Java.use('javax.crypto.spec.IvParameterSpec')).getIV()); } catch (e) {}
            console.log('[Cipher.init] ' + t + '  mode=' + mode + iv);
          }
        } catch (e) {}
        return this.init(mode, key, spec);
      };
    console.log('[+] hooked Cipher.init');
  } catch (e) {}
});

// --- Native OpenSSL fallback (Frida 17 API), in case MD5 runs in C.
setTimeout(function () {
  try {
    var p = null;
    if (typeof Module.findGlobalExportByName === 'function') p = Module.findGlobalExportByName('MD5_Update');
    if (!p) {
      Process.enumerateModules().forEach(function (m) {
        if (p || !/libcrypto|thing_security|security_algorithm/i.test(m.name)) return;
        try { var e = m.findExportByName('MD5_Update'); if (e) p = e; } catch (x) {}
      });
    }
    if (!p) { console.log('[i] native MD5_Update not found (ok if the Java MD5 hook fires)'); return; }
    Interceptor.attach(p, {
      onEnter: function (args) {
        var len = args[2].toInt32();
        if (len > 0 && len <= 40) {
          var arr = []; for (var i = 0; i < len; i++) arr.push(args[1].add(i).readU8());
          console.log('[native MD5 in] len=' + len + '  ascii="' + b2ascii(arr) + '"  hex=' + b2hex(arr));
        }
      }
    });
    console.log('[+] hooked native MD5_Update');
  } catch (e) { console.log('[-] native hook failed: ' + e); }
}, 2000);
