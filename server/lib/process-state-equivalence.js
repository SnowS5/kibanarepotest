"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Wazuh syscollector process state equivalence
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

/*
 * PROCESS STATE CODES
 *    Here are the different values that the s, stat and state output specifiers (header "STAT" or "S") will display to describe the state of a
 *    process.
 *    D    Uninterruptible sleep (usually IO)
 *    R    Running or runnable (on run queue)
 *    S    Interruptible sleep (waiting for an event to complete)
 *    T    Stopped, either by a job control signal or because it is being traced.
 *    W    paging (not valid since the 2.6.xx kernel)
 *    X    dead (should never be seen)
 *    Z    Defunct ("zombie") process, terminated but not reaped by its parent.
 *
 *    For BSD formats and when the stat keyword is used, additional characters may be displayed:
 *    <    high-priority (not nice to other users)
 *    N    low-priority (nice to other users)
 *    L    has pages locked into memory (for real-time and custom IO)
 *    s    is a session leader
 *    l    is multi-threaded (using CLONE_THREAD, like NPTL pthreads do)
 *    +    is in the foreground process group
 */
var _default = {
  t: 'tracing stop',
  P: 'Parked',
  I: 'Idle',
  D: 'Uninterruptible sleep (usually IO)',
  R: 'Running or runnable (on run queue)',
  S: 'Interruptible sleep (waiting for an event to complete)',
  T: 'Stopped, either by a job control signal or because it is being traced.',
  W: 'paging (not valid since the 2.6.xx kernel)',
  X: 'Dead (should never be seen)',
  Z: 'Defunct ("zombie") process, terminated but not reaped by its parent.',
  '<': 'High-priority (not nice to other users)',
  N: 'Low-priority (nice to other users)',
  L: 'Has pages locked into memory (for real-time and custom IO)',
  s: 'Is a session leader',
  l: 'Is multi-threaded (using CLONE_THREAD, like NPTL pthreads do)',
  '+': 'Is in the foreground process group'
};
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInByb2Nlc3Mtc3RhdGUtZXF1aXZhbGVuY2UudHMiXSwibmFtZXMiOlsidCIsIlAiLCJJIiwiRCIsIlIiLCJTIiwiVCIsIlciLCJYIiwiWiIsIk4iLCJMIiwicyIsImwiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7ZUFDZTtBQUNiQSxFQUFBQSxDQUFDLEVBQUUsY0FEVTtBQUViQyxFQUFBQSxDQUFDLEVBQUUsUUFGVTtBQUdiQyxFQUFBQSxDQUFDLEVBQUUsTUFIVTtBQUliQyxFQUFBQSxDQUFDLEVBQUUsb0NBSlU7QUFLYkMsRUFBQUEsQ0FBQyxFQUFFLG9DQUxVO0FBTWJDLEVBQUFBLENBQUMsRUFBRSx3REFOVTtBQU9iQyxFQUFBQSxDQUFDLEVBQUUsd0VBUFU7QUFRYkMsRUFBQUEsQ0FBQyxFQUFFLDRDQVJVO0FBU2JDLEVBQUFBLENBQUMsRUFBRSw2QkFUVTtBQVViQyxFQUFBQSxDQUFDLEVBQUUsc0VBVlU7QUFXYixPQUFLLHlDQVhRO0FBWWJDLEVBQUFBLENBQUMsRUFBRSxvQ0FaVTtBQWFiQyxFQUFBQSxDQUFDLEVBQUUsNERBYlU7QUFjYkMsRUFBQUEsQ0FBQyxFQUFFLHFCQWRVO0FBZWJDLEVBQUFBLENBQUMsRUFBRSwrREFmVTtBQWdCYixPQUFLO0FBaEJRLEMiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gV2F6dWggc3lzY29sbGVjdG9yIHByb2Nlc3Mgc3RhdGUgZXF1aXZhbGVuY2VcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5cbi8qXG4gKiBQUk9DRVNTIFNUQVRFIENPREVTXG4gKiAgICBIZXJlIGFyZSB0aGUgZGlmZmVyZW50IHZhbHVlcyB0aGF0IHRoZSBzLCBzdGF0IGFuZCBzdGF0ZSBvdXRwdXQgc3BlY2lmaWVycyAoaGVhZGVyIFwiU1RBVFwiIG9yIFwiU1wiKSB3aWxsIGRpc3BsYXkgdG8gZGVzY3JpYmUgdGhlIHN0YXRlIG9mIGFcbiAqICAgIHByb2Nlc3MuXG4gKiAgICBEICAgIFVuaW50ZXJydXB0aWJsZSBzbGVlcCAodXN1YWxseSBJTylcbiAqICAgIFIgICAgUnVubmluZyBvciBydW5uYWJsZSAob24gcnVuIHF1ZXVlKVxuICogICAgUyAgICBJbnRlcnJ1cHRpYmxlIHNsZWVwICh3YWl0aW5nIGZvciBhbiBldmVudCB0byBjb21wbGV0ZSlcbiAqICAgIFQgICAgU3RvcHBlZCwgZWl0aGVyIGJ5IGEgam9iIGNvbnRyb2wgc2lnbmFsIG9yIGJlY2F1c2UgaXQgaXMgYmVpbmcgdHJhY2VkLlxuICogICAgVyAgICBwYWdpbmcgKG5vdCB2YWxpZCBzaW5jZSB0aGUgMi42Lnh4IGtlcm5lbClcbiAqICAgIFggICAgZGVhZCAoc2hvdWxkIG5ldmVyIGJlIHNlZW4pXG4gKiAgICBaICAgIERlZnVuY3QgKFwiem9tYmllXCIpIHByb2Nlc3MsIHRlcm1pbmF0ZWQgYnV0IG5vdCByZWFwZWQgYnkgaXRzIHBhcmVudC5cbiAqXG4gKiAgICBGb3IgQlNEIGZvcm1hdHMgYW5kIHdoZW4gdGhlIHN0YXQga2V5d29yZCBpcyB1c2VkLCBhZGRpdGlvbmFsIGNoYXJhY3RlcnMgbWF5IGJlIGRpc3BsYXllZDpcbiAqICAgIDwgICAgaGlnaC1wcmlvcml0eSAobm90IG5pY2UgdG8gb3RoZXIgdXNlcnMpXG4gKiAgICBOICAgIGxvdy1wcmlvcml0eSAobmljZSB0byBvdGhlciB1c2VycylcbiAqICAgIEwgICAgaGFzIHBhZ2VzIGxvY2tlZCBpbnRvIG1lbW9yeSAoZm9yIHJlYWwtdGltZSBhbmQgY3VzdG9tIElPKVxuICogICAgcyAgICBpcyBhIHNlc3Npb24gbGVhZGVyXG4gKiAgICBsICAgIGlzIG11bHRpLXRocmVhZGVkICh1c2luZyBDTE9ORV9USFJFQUQsIGxpa2UgTlBUTCBwdGhyZWFkcyBkbylcbiAqICAgICsgICAgaXMgaW4gdGhlIGZvcmVncm91bmQgcHJvY2VzcyBncm91cFxuICovXG5leHBvcnQgZGVmYXVsdCB7XG4gIHQ6ICd0cmFjaW5nIHN0b3AnLFxuICBQOiAnUGFya2VkJyxcbiAgSTogJ0lkbGUnLFxuICBEOiAnVW5pbnRlcnJ1cHRpYmxlIHNsZWVwICh1c3VhbGx5IElPKScsXG4gIFI6ICdSdW5uaW5nIG9yIHJ1bm5hYmxlIChvbiBydW4gcXVldWUpJyxcbiAgUzogJ0ludGVycnVwdGlibGUgc2xlZXAgKHdhaXRpbmcgZm9yIGFuIGV2ZW50IHRvIGNvbXBsZXRlKScsXG4gIFQ6ICdTdG9wcGVkLCBlaXRoZXIgYnkgYSBqb2IgY29udHJvbCBzaWduYWwgb3IgYmVjYXVzZSBpdCBpcyBiZWluZyB0cmFjZWQuJyxcbiAgVzogJ3BhZ2luZyAobm90IHZhbGlkIHNpbmNlIHRoZSAyLjYueHgga2VybmVsKScsXG4gIFg6ICdEZWFkIChzaG91bGQgbmV2ZXIgYmUgc2VlbiknLFxuICBaOiAnRGVmdW5jdCAoXCJ6b21iaWVcIikgcHJvY2VzcywgdGVybWluYXRlZCBidXQgbm90IHJlYXBlZCBieSBpdHMgcGFyZW50LicsXG4gICc8JzogJ0hpZ2gtcHJpb3JpdHkgKG5vdCBuaWNlIHRvIG90aGVyIHVzZXJzKScsXG4gIE46ICdMb3ctcHJpb3JpdHkgKG5pY2UgdG8gb3RoZXIgdXNlcnMpJyxcbiAgTDogJ0hhcyBwYWdlcyBsb2NrZWQgaW50byBtZW1vcnkgKGZvciByZWFsLXRpbWUgYW5kIGN1c3RvbSBJTyknLFxuICBzOiAnSXMgYSBzZXNzaW9uIGxlYWRlcicsXG4gIGw6ICdJcyBtdWx0aS10aHJlYWRlZCAodXNpbmcgQ0xPTkVfVEhSRUFELCBsaWtlIE5QVEwgcHRocmVhZHMgZG8pJyxcbiAgJysnOiAnSXMgaW4gdGhlIGZvcmVncm91bmQgcHJvY2VzcyBncm91cCdcbn07XG4iXX0=