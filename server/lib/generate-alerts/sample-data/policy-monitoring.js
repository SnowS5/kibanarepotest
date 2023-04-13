"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.trojansData = exports.trojans = exports.title = exports.ruleDescription = exports.rootkitsData = exports.rootkits = exports.location = exports.decoder = void 0;

/*
 * Wazuh app - Policy monitoring sample alerts
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
// Policy monitoring
const title = ["Trojaned version of file detected."];
exports.title = title;
const ruleDescription = ["Host-based anomaly detection event (rootcheck).", "System Audit event."];
exports.ruleDescription = ruleDescription;
const location = 'rootcheck';
exports.location = location;
const decoder = {
  name: "rootcheck"
};
exports.decoder = decoder;
const rootkits = {
  Bash: ['/tmp/mcliZokhb', '/tmp/mclzaKmfa'],
  Adore: ['/dev/.shit/red.tgz', '/usr/lib/libt', '/usr/bin/adore'],
  TRK: ['usr/bin/soucemask', '/usr/bin/sourcemask'],
  Volc: ['/usr/lib/volc', '/usr/bin/volc'],
  Ramen: ['/usr/lib/ldlibps.so', '/usr/lib/ldliblogin.so', '/tmp/ramen.tgz'],
  Monkit: ['/lib/defs', '/usr/lib/libpikapp.a'],
  RSHA: ['usr/bin/kr4p', 'usr/bin/n3tstat', 'usr/bin/chsh2'],
  Omega: ['/dev/chr'],
  "Rh-Sharpe": ['/usr/bin/.ps', '/bin/.lpstree', '/bin/ldu', '/bin/lkillall'],
  Showtee: ['/usr/lib/.wormie', '/usr/lib/.kinetic', '/usr/include/addr.h'],
  LDP: ['/dev/.kork', '/bin/.login', '/bin/.ps'],
  Slapper: ['/tmp/.bugtraq', '/tmp/.bugtraq.c', '/tmp/.b', '/tmp/httpd', '/tmp/.font-unix/.cinik'],
  Knark: ['/dev/.pizda', '/proc/knark'],
  ZK: ['/usr/share/.zk', 'etc/1ssue.net', 'usr/X11R6/.zk/xfs'],
  Suspicious: ['etc/rc.d/init.d/rc.modules', 'lib/ldd.so', 'usr/bin/ddc', 'usr/bin/ishit', 'lib/.so', 'usr/bin/atm', 'tmp/.cheese', 'dev/srd0', 'dev/hd7', 'usr/man/man3/psid']
};
exports.rootkits = rootkits;
const rootkitsData = {
  "data": {
    "title": "Rootkit '{_rootkit_category}' detected by the presence of file '{_rootkit_file}'."
  },
  "rule": {
    "firedtimes": 1,
    "mail": false,
    "level": 7,
    "description": "Host-based anomaly detection event (rootcheck).",
    "groups": ["wazuh", "rootcheck"],
    "id": "510",
    "gdpr": ["IV_35.7.d"]
  },
  "full_log": "Rootkit '{_rootkit_category}' detected by the presence of file '{_rootkit_file}'."
};
exports.rootkitsData = rootkitsData;
const trojans = [{
  file: '/usr/bin/grep',
  signature: 'bash|givemer'
}, {
  file: '/usr/bin/egrep',
  signature: 'bash|^/bin/sh|file\.h|proc\.h|/dev/|^/bin/.*sh'
}, {
  file: '/usr/bin/find',
  signature: 'bash|/dev/[^tnlcs]|/prof|/home/virus|file\.h'
}, {
  file: '/usr/bin/lsof',
  signature: '/prof|/dev/[^apcmnfk]|proc\.h|bash|^/bin/sh|/dev/ttyo|/dev/ttyp'
}, {
  file: '/usr/bin/netstat',
  signature: 'bash|^/bin/sh|/dev/[^aik]|/prof|grep|addr\.h'
}, {
  file: '/usr/bin/top',
  signature: '/dev/[^npi3st%]|proc\.h|/prof/'
}, {
  file: '/usr/bin/ps',
  signature: '/dev/ttyo|\.1proc|proc\.h|bash|^/bin/sh'
}, {
  file: '/usr/bin/tcpdump',
  signature: 'bash|^/bin/sh|file\.h|proc\.h|/dev/[^bu]|^/bin/.*sh'
}, {
  file: '/usr/bin/pidof',
  signature: 'bash|^/bin/sh|file\.h|proc\.h|/dev/[^f]|^/bin/.*sh'
}, {
  file: '/usr/bin/fuser',
  signature: 'bash|^/bin/sh|file\.h|proc\.h|/dev/[a-dtz]|^/bin/.*sh'
}, {
  file: '/usr/bin/w',
  signature: 'uname -a|proc\.h|bash'
}];
exports.trojans = trojans;
const trojansData = {
  "rule": {
    "firedtimes": 2,
    "mail": false,
    "level": 7,
    "description": "Host-based anomaly detection event (rootcheck).",
    "groups": ["wazuh", "rootcheck"],
    "id": "510",
    "gdpr": ["IV_35.7.d"]
  },
  "full_log": "Trojaned version of file '{data.file}' detected. Signature used: '{_trojan_signature}' (Generic)."
};
exports.trojansData = trojansData;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInBvbGljeS1tb25pdG9yaW5nLmpzIl0sIm5hbWVzIjpbInRpdGxlIiwicnVsZURlc2NyaXB0aW9uIiwibG9jYXRpb24iLCJkZWNvZGVyIiwibmFtZSIsInJvb3RraXRzIiwiQmFzaCIsIkFkb3JlIiwiVFJLIiwiVm9sYyIsIlJhbWVuIiwiTW9ua2l0IiwiUlNIQSIsIk9tZWdhIiwiU2hvd3RlZSIsIkxEUCIsIlNsYXBwZXIiLCJLbmFyayIsIlpLIiwiU3VzcGljaW91cyIsInJvb3RraXRzRGF0YSIsInRyb2phbnMiLCJmaWxlIiwic2lnbmF0dXJlIiwidHJvamFuc0RhdGEiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFDTyxNQUFNQSxLQUFLLEdBQUcsQ0FBQyxvQ0FBRCxDQUFkOztBQUNBLE1BQU1DLGVBQWUsR0FBRyxDQUFDLGlEQUFELEVBQW9ELHFCQUFwRCxDQUF4Qjs7QUFFQSxNQUFNQyxRQUFRLEdBQUcsV0FBakI7O0FBRUEsTUFBTUMsT0FBTyxHQUFHO0FBQ3JCQyxFQUFBQSxJQUFJLEVBQUU7QUFEZSxDQUFoQjs7QUFJQSxNQUFNQyxRQUFRLEdBQUc7QUFDdEJDLEVBQUFBLElBQUksRUFBRSxDQUFDLGdCQUFELEVBQW1CLGdCQUFuQixDQURnQjtBQUV0QkMsRUFBQUEsS0FBSyxFQUFFLENBQUMsb0JBQUQsRUFBdUIsZUFBdkIsRUFBd0MsZ0JBQXhDLENBRmU7QUFHdEJDLEVBQUFBLEdBQUcsRUFBRSxDQUFDLG1CQUFELEVBQXFCLHFCQUFyQixDQUhpQjtBQUl0QkMsRUFBQUEsSUFBSSxFQUFFLENBQUMsZUFBRCxFQUFrQixlQUFsQixDQUpnQjtBQUt0QkMsRUFBQUEsS0FBSyxFQUFFLENBQUMscUJBQUQsRUFBdUIsd0JBQXZCLEVBQWlELGdCQUFqRCxDQUxlO0FBTXRCQyxFQUFBQSxNQUFNLEVBQUUsQ0FBQyxXQUFELEVBQWMsc0JBQWQsQ0FO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QUFNLEtBTkE7QUFPTixZQUFRLENBQUMsV0FBRDtBQVBGLEdBRGlCO0FBVXpCLGNBQVk7QUFWYSxDQUFwQiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBQb2xpY3kgbW9uaXRvcmluZyBzYW1wbGUgYWxlcnRzXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuXG4vLyBQb2xpY3kgbW9uaXRvcmluZ1xuZXhwb3J0IGNvbnN0IHRpdGxlID0gW1wiVHJvamFuZWQgdmVyc2lvbiBvZiBmaWxlIGRldGVjdGVkLlwiXTtcbmV4cG9ydCBjb25zdCBydWxlRGVzY3JpcHRpb24gPSBbXCJIb3N0LWJhc2VkIGFub21hbHkgZGV0ZWN0aW9uIGV2ZW50IChyb290Y2hlY2spLlwiLCBcIlN5c3RlbSBBdWRpdCBldmVudC5cIl07XG5cbmV4cG9ydCBjb25zdCBsb2NhdGlvbiA9ICdyb290Y2hlY2snO1xuXG5leHBvcnQgY29uc3QgZGVjb2RlciA9IHtcbiAgbmFtZTogXCJyb290Y2hlY2tcIlxufTtcblxuZXhwb3J0IGNvbnN0IHJvb3RraXRzID0ge1xuICBCYXNoOiBbJy90bXAvbWNsaVpva2hiJywgJy90bXAvbWNsemFLbWZhJ10sXG4gIEFkb3JlOiBbJy9kZXYvLnNoaXQvcmVkLnRneicsICcvdXNyL2xpYi9saWJ0JywgJy91c3IvYmluL2Fkb3JlJ10sXG4gIFRSSzogWyd1c3IvYmluL3NvdWNlbWFzaycsJy91c3IvYmluL3NvdXJjZW1hc2snXSxcbiAgVm9sYzogWycvdXNyL2xpYi92b2xjJywgJy91c3IvYmluL3ZvbGMnXSxcbiAgUmFtZW46IFsnL3Vzci9saWIvbGRsaWJwcy5zbycsJy91c3IvbGliL2xkbGlibG9naW4uc28nLCAnL3RtcC9yYW1lbi50Z3onXSxcbiAgTW9ua2l0OiBbJy9saWIvZGVmcycsICcvdXNyL2xpYi9saWJwaWthcHAuYSddLFxuICBSU0hBOiBbJ3Vzci9iaW4va3I0cCcsICd1c3IvYmluL24zdHN0YXQnLCAndXNyL2Jpbi9jaHNoMiddLFxuICBPbWVnYTogWycvZGV2L2NociddLFxuICBcIlJoLVNoYXJwZVwiOiBbJy91c3IvYmluLy5wcycsICcvYmluLy5scHN0cmVlJywgJy9iaW4vbGR1JywgJy9iaW4vbGtpbGxhbGwnXSxcbiAgU2hvd3RlZTogWycvdXNyL2xpYi8ud29ybWllJywnL3Vzci9saWIvLmtpbmV0aWMnLCcvdXNyL2luY2x1ZGUvYWRkci5oJ10sXG4gIExEUDogWycvZGV2Ly5rb3JrJywgJy9iaW4vLmxvZ2luJywgJy9iaW4vLnBzJ10sXG4gIFNsYXBwZXI6IFsnL3RtcC8uYnVndHJhcScsJy90bXAvLmJ1Z3RyYXEuYycsICcvdG1wLy5iJywgJy90bXAvaHR0cGQnLCAnL3RtcC8uZm9udC11bml4Ly5jaW5payddLFxuICBLbmFyazogWycvZGV2Ly5waXpkYScsICcvcHJvYy9rbmFyayddLFxuICBaSzogWycvdXNyL3NoYXJlLy56aycsICdldGMvMXNzdWUubmV0JywgJ3Vzci9YMTFSNi8uemsveGZzJ10sXG4gIFN1c3BpY2lvdXM6IFsnZXRjL3JjLmQvaW5pdC5kL3JjLm1vZHVsZXMnLCAnbGliL2xkZC5zbycsICd1c3IvYmluL2RkYycsICd1c3IvYmluL2lzaGl0JywgJ2xpYi8uc28nLCAndXNyL2Jpbi9hdG0nLCAndG1wLy5jaGVlc2UnLCAnZGV2L3NyZDAnLCAnZGV2L2hkNycsICd1c3IvbWFuL21hbjMvcHNpZCddXG59O1xuXG5leHBvcnQgY29uc3Qgcm9vdGtpdHNEYXRhID0ge1xuICBcImRhdGFcIjoge1xuICAgIFwidGl0bGVcIjogXCJSb290a2l0ICd7X3Jvb3RraXRfY2F0ZWdvcnl9JyBkZXRlY3RlZCBieSB0aGUgcHJlc2VuY2Ugb2YgZmlsZSAne19yb290a2l0X2ZpbGV9Jy5cIlxuICB9LFxuICBcInJ1bGVcIjoge1xuICAgIFwiZmlyZWR0aW1lc1wiOiAxLFxuICAgIFwibWFpbFwiOiBmYWxzZSxcbiAgICBcImxldmVsXCI6IDcsXG4gICAgXCJkZXNjcmlwdGlvblwiOiBcIkhvc3QtYmFzZWQgYW5vbWFseSBkZXRlY3Rpb24gZXZlbnQgKHJvb3RjaGVjaykuXCIsXG4gICAgXCJncm91cHNcIjogW1wid2F6dWhcIixcInJvb3RjaGVja1wiXSxcbiAgICBcImlkXCI6IFwiNTEwXCIsXG4gICAgXCJnZHByXCI6IFtcIklWXzM1LjcuZFwiXVxuICB9LFxuICBcImZ1bGxfbG9nXCI6IFwiUm9vdGtpdCAne19yb290a2l0X2NhdGVnb3J5fScgZGV0ZWN0ZWQgYnkgdGhlIHByZXNlbmNlIG9mIGZpbGUgJ3tfcm9vdGtpdF9maWxlfScuXCIsXG59O1xuXG5leHBvcnQgY29uc3QgdHJvamFucyA9IFtcbiAge2ZpbGU6ICcvdXNyL2Jpbi9ncmVwJywgc2lnbmF0dXJlOiAnYmFzaHxnaXZlbWVyJ30sXG4gIHtmaWxlOiAnL3Vzci9iaW4vZWdyZXAnLCBzaWduYXR1cmU6ICdiYXNofF4vYmluL3NofGZpbGVcXC5ofHByb2NcXC5ofC9kZXYvfF4vYmluLy4qc2gnfSxcbiAge2ZpbGU6ICcvdXNyL2Jpbi9maW5kJywgc2lnbmF0dXJlOiAnYmFzaHwvZGV2L1tedG5sY3NdfC9wcm9mfC9ob21lL3ZpcnVzfGZpbGVcXC5oJ30sXG4gIHtmaWxlOiAnL3Vzci9iaW4vbHNvZicsIHNpZ25hdHVyZTogJy9wcm9mfC9kZXYvW15hcGNtbmZrXXxwcm9jXFwuaHxiYXNofF4vYmluL3NofC9kZXYvdHR5b3wvZGV2L3R0eXAnfSxcbiAge2ZpbGU6ICcvdXNyL2Jpbi9uZXRzdGF0Jywgc2lnbmF0dXJlOiAnYmFzaHxeL2Jpbi9zaHwvZGV2L1teYWlrXXwvcHJvZnxncmVwfGFkZHJcXC5oJ30sXG4gIHtmaWxlOiAnL3Vzci9iaW4vdG9wJywgc2lnbmF0dXJlOiAnL2Rldi9bXm5waTNzdCVdfHByb2NcXC5ofC9wcm9mLyd9LFxuICB7ZmlsZTogJy91c3IvYmluL3BzJywgc2lnbmF0dXJlOiAnL2Rldi90dHlvfFxcLjFwcm9jfHByb2NcXC5ofGJhc2h8Xi9iaW4vc2gnfSxcbiAge2ZpbGU6ICcvdXNyL2Jpbi90Y3BkdW1wJywgc2lnbmF0dXJlOiAnYmFzaHxeL2Jpbi9zaHxmaWxlXFwuaHxwcm9jXFwuaHwvZGV2L1teYnVdfF4vYmluLy4qc2gnfSxcbiAge2ZpbGU6ICcvdXNyL2Jpbi9waWRvZicsIHNpZ25hdHVyZTogJ2Jhc2h8Xi9iaW4vc2h8ZmlsZVxcLmh8cHJvY1xcLmh8L2Rldi9bXmZdfF4vYmluLy4qc2gnfSxcbiAge2ZpbGU6ICcvdXNyL2Jpbi9mdXNlcicsIHNpZ25hdHVyZTogJ2Jhc2h8Xi9iaW4vc2h8ZmlsZVxcLmh8cHJvY1xcLmh8L2Rldi9bYS1kdHpdfF4vYmluLy4qc2gnfSxcbiAge2ZpbGU6ICcvdXNyL2Jpbi93Jywgc2lnbmF0dXJlOiAndW5hbWUgLWF8cHJvY1xcLmh8YmFzaCd9LFxuXTtcblxuZXhwb3J0IGNvbnN0IHRyb2phbnNEYXRhID0ge1xuICBcInJ1bGVcIjoge1xuICAgIFwiZmlyZWR0aW1lc1wiOiAyLFxuICAgIFwibWFpbFwiOiBmYWxzZSxcbiAgICBcImxldmVsXCI6IDcsXG4gICAgXCJkZXNjcmlwdGlvblwiOiBcIkhvc3QtYmFzZWQgYW5vbWFseSBkZXRlY3Rpb24gZXZlbnQgKHJvb3RjaGVjaykuXCIsXG4gICAgXCJncm91cHNcIjogW1wid2F6dWhcIixcInJvb3RjaGVja1wiXSxcbiAgICBcImlkXCI6IFwiNTEwXCIsXG4gICAgXCJnZHByXCI6IFtcIklWXzM1LjcuZFwiXVxuICB9LFxuICBcImZ1bGxfbG9nXCI6IFwiVHJvamFuZWQgdmVyc2lvbiBvZiBmaWxlICd7ZGF0YS5maWxlfScgZGV0ZWN0ZWQuIFNpZ25hdHVyZSB1c2VkOiAne190cm9qYW5fc2lnbmF0dXJlfScgKEdlbmVyaWMpLlwiLFxufTtcbiJdfQ==