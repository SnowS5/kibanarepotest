"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.nistRequirementsFile = void 0;

/*
 * Wazuh app - Module for NIST 800-53 requirements
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const nistRequirementsFile = {
  'AC.2': 'ACCOUNT MANAGEMENT - Identifies and selects the following types of information system accounts to support organizational missions/business functions.',
  'AC.6': 'LEAST PRIVILEGE - The organization employs the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) which are necessary to accomplish assigned tasks in accordance with organizational missions and business functions.',
  'AC.7': 'UNSUCCESSFUL LOGON ATTEMPTS - Enforces a limit of consecutive invalid logon attempts by a user during a time period.',
  'AC.12': 'SESSION TERMINATION - The information system automatically terminates a user session.',
  'AU.5': 'RESPONSE TO AUDIT PROCESSING FAILURES - The information system alerts organization-defined personnel or roles in the event of an audit processing failure and takes organization-defined actions to be taken (e.g., shut down information system, overwrite oldest audit records, stop generating audit records).',
  'AU.6': 'AUDIT REVIEW, ANALYSIS, AND REPORTING - Reviews and analyzes information system audit records.',
  'AU.8': 'TIME STAMPS - Uses internal system clocks to generate time stamps for audit records and records time stamps for audit records.',
  'AU.9': 'PROTECTION OF AUDIT INFORMATION - The information system protects audit information and audit tools from unauthorized access, modification, and deletion.',
  'AU.12': 'AUDIT GENERATION - The information system provides audit record generation capability for the auditable events at organization-defined information system components, allows organization-defined personnel or roles to select which auditable events are to be audited by specific components of the information system and generates audit records.',
  'CA.3': 'SYSTEM INTERCONNECTIONS - Authorizes connections from the information system to other information systems through the use of Interconnection Security Agreements, Documents, for each interconnection, the interface characteristics, security requirements, and the nature of the information communicated and Reviews and updates Interconnection Security Agreements ',
  'CM.1': 'CONFIGURATION MANAGEMENT POLICY AND PROCEDURES - Develops, documents, and disseminates to a configuration management policy. Revies and updates the current configuration management policy and procedures.',
  'CM.3': 'CONFIGURATION CHANGE CONTROL - The organization determines the types of changes to the information system that are configuration-controlled. ',
  'CM.5': 'ACCESS RESTRICTIONS FOR CHANGE - The organization defines, documents, approves, and enforces physical and logical access restrictions associated with changes to the information system.',
  'IA.4': 'IDENTIFIER MANAGEMENT - The organization manages information system identifiers by: Receiving authorization from organization-defined personnel or roles to assign an individual, group, role, or device identifier. Selecting an identifier that identifies an individual, group, role, or device. Assigning the identifier to the intended individual, group, role, or device. Preventing reuse of identifiers for a organization-defined time period. Disabling the identifier after organization-defined time period of inactivity.',
  'IA.5': 'AUTHENTICATOR MANAGEMENT - The organization manages information system authenticators by verifying, as part of the initial authenticator distribution, the identity of the individual, group role, or device receiving the authenticator.',
  'IA.10': 'ADAPTIVE IDENTIFICATION AND AUTHENTICATION - The organization requires that individuals accessing the information system employ organization-defined supplemental authentication techniques or mechanisms under specific organization-defined circumstances or situations. ',
  'SA.11': 'DEVELOPER SECURITY TESTING AND EVALUATION - The organization requires the developer of the information system, system component, or information system service to create and implement a security assessment plan.',
  'SC.2': 'APPLICATION PARTITIONING - The information system separates user functionality (including user interface services) from information system management functionality.',
  'SC.7': 'BOUNDARY PROTECTION - The information system monitors and controls communications at the external boundary of the system and at key internal boundaries within the system.',
  'SC.8': 'TRANSMISSION CONFIDENTIALITY AND INTEGRITY - The information system protects the confidentiality and integrity of transmitted information.',
  'SI.2': 'FLAW REMEDIATION - The organization identifies, reports, and corrects information system flaws; tests software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; installs security-relevant software and firmware updates within organizationdefined time period of the release of the updates and  incorporates flaw remediation into the organizational configuration management process.',
  'SI.3': 'MALICIOUS CODE PROTECTION - The organization employs malicious code protection mechanisms at information system entry and exit points to detect and eradicate malicious code, updates malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures, configures malicious code protection mechanisms and addresses the receipt of false positives during malicious code detection and eradication and the resulting potential impact on the availability of the information system.',
  'SI.7': 'SOFTWARE, FIRMWARE, AND INFORMATION INTEGRITY - The organization employs integrity verification tools to detect unauthorized changes to organization-defined software, firmware, and information.'
};
exports.nistRequirementsFile = nistRequirementsFile;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5pc3QtcmVxdWlyZW1lbnRzLnRzIl0sIm5hbWVzIjpbIm5pc3RSZXF1aXJlbWVudHNGaWxlIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPLE1BQU1BLG9CQUFvQixHQUFHO0FBQ2xDLFVBQ0UsdUpBRmdDO0FBR2xDLFVBQ0UsdVJBSmdDO0FBS2xDLFVBQ0Usc0hBTmdDO0FBT2xDLFdBQ0UsdUZBUmdDO0FBU2xDLFVBQ0UsbVRBVmdDO0FBV2xDLFVBQ0UsZ0dBWmdDO0FBYWxDLFVBQ0UsZ0lBZGdDO0FBZWxDLFVBQ0UsMkpBaEJnQztBQWlCbEMsV0FDRSx1VkFsQmdDO0FBbUJsQyxVQUNFLDBXQXBCZ0M7QUFxQmxDLFVBQ0UsNk1BdEJnQztBQXVCbEMsVUFDRSwrSUF4QmdDO0FBeUJsQyxVQUNFLDBMQTFCZ0M7QUEyQmxDLFVBQ0UseWdCQTVCZ0M7QUE2QmxDLFVBQ0UsMk9BOUJnQztBQStCbEMsV0FDRSw2UUFoQ2dDO0FBaUNsQyxXQUNFLG9OQWxDZ0M7QUFtQ2xDLFVBQ0Usc0tBcENnQztBQXFDbEMsVUFDRSw0S0F0Q2dDO0FBdUNsQyxVQUNFLDRJQXhDZ0M7QUF5Q2xDLFVBQ0UsOGJBMUNnQztBQTJDbEMsVUFDRSxpakJBNUNnQztBQTZDbEMsVUFDRTtBQTlDZ0MsQ0FBN0IiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gTW9kdWxlIGZvciBOSVNUIDgwMC01MyByZXF1aXJlbWVudHNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgY29uc3QgbmlzdFJlcXVpcmVtZW50c0ZpbGUgPSB7XG4gICdBQy4yJzpcbiAgICAnQUNDT1VOVCBNQU5BR0VNRU5UIC0gSWRlbnRpZmllcyBhbmQgc2VsZWN0cyB0aGUgZm9sbG93aW5nIHR5cGVzIG9mIGluZm9ybWF0aW9uIHN5c3RlbSBhY2NvdW50cyB0byBzdXBwb3J0IG9yZ2FuaXphdGlvbmFsIG1pc3Npb25zL2J1c2luZXNzIGZ1bmN0aW9ucy4nLFxuICAnQUMuNic6XG4gICAgJ0xFQVNUIFBSSVZJTEVHRSAtIFRoZSBvcmdhbml6YXRpb24gZW1wbG95cyB0aGUgcHJpbmNpcGxlIG9mIGxlYXN0IHByaXZpbGVnZSwgYWxsb3dpbmcgb25seSBhdXRob3JpemVkIGFjY2Vzc2VzIGZvciB1c2VycyAob3IgcHJvY2Vzc2VzIGFjdGluZyBvbiBiZWhhbGYgb2YgdXNlcnMpIHdoaWNoIGFyZSBuZWNlc3NhcnkgdG8gYWNjb21wbGlzaCBhc3NpZ25lZCB0YXNrcyBpbiBhY2NvcmRhbmNlIHdpdGggb3JnYW5pemF0aW9uYWwgbWlzc2lvbnMgYW5kIGJ1c2luZXNzIGZ1bmN0aW9ucy4nLFxuICAnQUMuNyc6XG4gICAgJ1VOU1VDQ0VTU0ZVTCBMT0dPTiBBVFRFTVBUUyAtIEVuZm9yY2VzIGEgbGltaXQgb2YgY29uc2VjdXRpdmUgaW52YWxpZCBsb2dvbiBhdHRlbXB0cyBieSBhIHVzZXIgZHVyaW5nIGEgdGltZSBwZXJpb2QuJyxcbiAgJ0FDLjEyJzpcbiAgICAnU0VTU0lPTiBURVJNSU5BVElPTiAtIFRoZSBpbmZvcm1hdGlvbiBzeXN0ZW0gYXV0b21hdGljYWxseSB0ZXJtaW5hdGVzIGEgdXNlciBzZXNzaW9uLicsXG4gICdBVS41JzpcbiAgICAnUkVTUE9OU0UgVE8gQVVESVQgUFJPQ0VTU0lORyBGQUlMVVJFUyAtIFRoZSBpbmZvcm1hdGlvbiBzeXN0ZW0gYWxlcnRzIG9yZ2FuaXphdGlvbi1kZWZpbmVkIHBlcnNvbm5lbCBvciByb2xlcyBpbiB0aGUgZXZlbnQgb2YgYW4gYXVkaXQgcHJvY2Vzc2luZyBmYWlsdXJlIGFuZCB0YWtlcyBvcmdhbml6YXRpb24tZGVmaW5lZCBhY3Rpb25zIHRvIGJlIHRha2VuIChlLmcuLCBzaHV0IGRvd24gaW5mb3JtYXRpb24gc3lzdGVtLCBvdmVyd3JpdGUgb2xkZXN0IGF1ZGl0IHJlY29yZHMsIHN0b3AgZ2VuZXJhdGluZyBhdWRpdCByZWNvcmRzKS4nLFxuICAnQVUuNic6XG4gICAgJ0FVRElUIFJFVklFVywgQU5BTFlTSVMsIEFORCBSRVBPUlRJTkcgLSBSZXZpZXdzIGFuZCBhbmFseXplcyBpbmZvcm1hdGlvbiBzeXN0ZW0gYXVkaXQgcmVjb3Jkcy4nLFxuICAnQVUuOCc6XG4gICAgJ1RJTUUgU1RBTVBTIC0gVXNlcyBpbnRlcm5hbCBzeXN0ZW0gY2xvY2tzIHRvIGdlbmVyYXRlIHRpbWUgc3RhbXBzIGZvciBhdWRpdCByZWNvcmRzIGFuZCByZWNvcmRzIHRpbWUgc3RhbXBzIGZvciBhdWRpdCByZWNvcmRzLicsXG4gICdBVS45JzpcbiAgICAnUFJPVEVDVElPTiBPRiBBVURJVCBJTkZPUk1BVElPTiAtIFRoZSBpbmZvcm1hdGlvbiBzeXN0ZW0gcHJvdGVjdHMgYXVkaXQgaW5mb3JtYXRpb24gYW5kIGF1ZGl0IHRvb2xzIGZyb20gdW5hdXRob3JpemVkIGFjY2VzcywgbW9kaWZpY2F0aW9uLCBhbmQgZGVsZXRpb24uJyxcbiAgJ0FVLjEyJzpcbiAgICAnQVVESVQgR0VORVJBVElPTiAtIFRoZSBpbmZvcm1hdGlvbiBzeXN0ZW0gcHJvdmlkZXMgYXVkaXQgcmVjb3JkIGdlbmVyYXRpb24gY2FwYWJpbGl0eSBmb3IgdGhlIGF1ZGl0YWJsZSBldmVudHMgYXQgb3JnYW5pemF0aW9uLWRlZmluZWQgaW5mb3JtYXRpb24gc3lzdGVtIGNvbXBvbmVudHMsIGFsbG93cyBvcmdhbml6YXRpb24tZGVmaW5lZCBwZXJzb25uZWwgb3Igcm9sZXMgdG8gc2VsZWN0IHdoaWNoIGF1ZGl0YWJsZSBldmVudHMgYXJlIHRvIGJlIGF1ZGl0ZWQgYnkgc3BlY2lmaWMgY29tcG9uZW50cyBvZiB0aGUgaW5mb3JtYXRpb24gc3lzdGVtIGFuZCBnZW5lcmF0ZXMgYXVkaXQgcmVjb3Jkcy4nLFxuICAnQ0EuMyc6XG4gICAgJ1NZU1RFTSBJTlRFUkNPTk5FQ1RJT05TIC0gQXV0aG9yaXplcyBjb25uZWN0aW9ucyBmcm9tIHRoZSBpbmZvcm1hdGlvbiBzeXN0ZW0gdG8gb3RoZXIgaW5mb3JtYXRpb24gc3lzdGVtcyB0aHJvdWdoIHRoZSB1c2Ugb2YgSW50ZXJjb25uZWN0aW9uIFNlY3VyaXR5IEFncmVlbWVudHMsIERvY3VtZW50cywgZm9yIGVhY2ggaW50ZXJjb25uZWN0aW9uLCB0aGUgaW50ZXJmYWNlIGNoYXJhY3RlcmlzdGljcywgc2VjdXJpdHkgcmVxdWlyZW1lbnRzLCBhbmQgdGhlIG5hdHVyZSBvZiB0aGUgaW5mb3JtYXRpb24gY29tbXVuaWNhdGVkIGFuZCBSZXZpZXdzIGFuZCB1cGRhdGVzIEludGVyY29ubmVjdGlvbiBTZWN1cml0eSBBZ3JlZW1lbnRzICcsXG4gICdDTS4xJzpcbiAgICAnQ09ORklHVVJBVElPTiBNQU5BR0VNRU5UIFBPTElDWSBBTkQgUFJPQ0VEVVJFUyAtIERldmVsb3BzLCBkb2N1bWVudHMsIGFuZCBkaXNzZW1pbmF0ZXMgdG8gYSBjb25maWd1cmF0aW9uIG1hbmFnZW1lbnQgcG9saWN5LiBSZXZpZXMgYW5kIHVwZGF0ZXMgdGhlIGN1cnJlbnQgY29uZmlndXJhdGlvbiBtYW5hZ2VtZW50IHBvbGljeSBhbmQgcHJvY2VkdXJlcy4nLFxuICAnQ00uMyc6XG4gICAgJ0NPTkZJR1VSQVRJT04gQ0hBTkdFIENPTlRST0wgLSBUaGUgb3JnYW5pemF0aW9uIGRldGVybWluZXMgdGhlIHR5cGVzIG9mIGNoYW5nZXMgdG8gdGhlIGluZm9ybWF0aW9uIHN5c3RlbSB0aGF0IGFyZSBjb25maWd1cmF0aW9uLWNvbnRyb2xsZWQuICcsXG4gICdDTS41JzpcbiAgICAnQUNDRVNTIFJFU1RSSUNUSU9OUyBGT1IgQ0hBTkdFIC0gVGhlIG9yZ2FuaXphdGlvbiBkZWZpbmVzLCBkb2N1bWVudHMsIGFwcHJvdmVzLCBhbmQgZW5mb3JjZXMgcGh5c2ljYWwgYW5kIGxvZ2ljYWwgYWNjZXNzIHJlc3RyaWN0aW9ucyBhc3NvY2lhdGVkIHdpdGggY2hhbmdlcyB0byB0aGUgaW5mb3JtYXRpb24gc3lzdGVtLicsXG4gICdJQS40JzpcbiAgICAnSURFTlRJRklFUiBNQU5BR0VNRU5UIC0gVGhlIG9yZ2FuaXphdGlvbiBtYW5hZ2VzIGluZm9ybWF0aW9uIHN5c3RlbSBpZGVudGlmaWVycyBieTogUmVjZWl2aW5nIGF1dGhvcml6YXRpb24gZnJvbSBvcmdhbml6YXRpb24tZGVmaW5lZCBwZXJzb25uZWwgb3Igcm9sZXMgdG8gYXNzaWduIGFuIGluZGl2aWR1YWwsIGdyb3VwLCByb2xlLCBvciBkZXZpY2UgaWRlbnRpZmllci4gU2VsZWN0aW5nIGFuIGlkZW50aWZpZXIgdGhhdCBpZGVudGlmaWVzIGFuIGluZGl2aWR1YWwsIGdyb3VwLCByb2xlLCBvciBkZXZpY2UuIEFzc2lnbmluZyB0aGUgaWRlbnRpZmllciB0byB0aGUgaW50ZW5kZWQgaW5kaXZpZHVhbCwgZ3JvdXAsIHJvbGUsIG9yIGRldmljZS4gUHJldmVudGluZyByZXVzZSBvZiBpZGVudGlmaWVycyBmb3IgYSBvcmdhbml6YXRpb24tZGVmaW5lZCB0aW1lIHBlcmlvZC4gRGlzYWJsaW5nIHRoZSBpZGVudGlmaWVyIGFmdGVyIG9yZ2FuaXphdGlvbi1kZWZpbmVkIHRpbWUgcGVyaW9kIG9mIGluYWN0aXZpdHkuJyxcbiAgJ0lBLjUnOlxuICAgICdBVVRIRU5USUNBVE9SIE1BTkFHRU1FTlQgLSBUaGUgb3JnYW5pemF0aW9uIG1hbmFnZXMgaW5mb3JtYXRpb24gc3lzdGVtIGF1dGhlbnRpY2F0b3JzIGJ5IHZlcmlmeWluZywgYXMgcGFydCBvZiB0aGUgaW5pdGlhbCBhdXRoZW50aWNhdG9yIGRpc3RyaWJ1dGlvbiwgdGhlIGlkZW50aXR5IG9mIHRoZSBpbmRpdmlkdWFsLCBncm91cCByb2xlLCBvciBkZXZpY2UgcmVjZWl2aW5nIHRoZSBhdXRoZW50aWNhdG9yLicsXG4gICdJQS4xMCc6XG4gICAgJ0FEQVBUSVZFIElERU5USUZJQ0FUSU9OIEFORCBBVVRIRU5USUNBVElPTiAtIFRoZSBvcmdhbml6YXRpb24gcmVxdWlyZXMgdGhhdCBpbmRpdmlkdWFscyBhY2Nlc3NpbmcgdGhlIGluZm9ybWF0aW9uIHN5c3RlbSBlbXBsb3kgb3JnYW5pemF0aW9uLWRlZmluZWQgc3VwcGxlbWVudGFsIGF1dGhlbnRpY2F0aW9uIHRlY2huaXF1ZXMgb3IgbWVjaGFuaXNtcyB1bmRlciBzcGVjaWZpYyBvcmdhbml6YXRpb24tZGVmaW5lZCBjaXJjdW1zdGFuY2VzIG9yIHNpdHVhdGlvbnMuICcsXG4gICdTQS4xMSc6XG4gICAgJ0RFVkVMT1BFUiBTRUNVUklUWSBURVNUSU5HIEFORCBFVkFMVUFUSU9OIC0gVGhlIG9yZ2FuaXphdGlvbiByZXF1aXJlcyB0aGUgZGV2ZWxvcGVyIG9mIHRoZSBpbmZvcm1hdGlvbiBzeXN0ZW0sIHN5c3RlbSBjb21wb25lbnQsIG9yIGluZm9ybWF0aW9uIHN5c3RlbSBzZXJ2aWNlIHRvIGNyZWF0ZSBhbmQgaW1wbGVtZW50IGEgc2VjdXJpdHkgYXNzZXNzbWVudCBwbGFuLicsXG4gICdTQy4yJzpcbiAgICAnQVBQTElDQVRJT04gUEFSVElUSU9OSU5HIC0gVGhlIGluZm9ybWF0aW9uIHN5c3RlbSBzZXBhcmF0ZXMgdXNlciBmdW5jdGlvbmFsaXR5IChpbmNsdWRpbmcgdXNlciBpbnRlcmZhY2Ugc2VydmljZXMpIGZyb20gaW5mb3JtYXRpb24gc3lzdGVtIG1hbmFnZW1lbnQgZnVuY3Rpb25hbGl0eS4nLFxuICAnU0MuNyc6XG4gICAgJ0JPVU5EQVJZIFBST1RFQ1RJT04gLSBUaGUgaW5mb3JtYXRpb24gc3lzdGVtIG1vbml0b3JzIGFuZCBjb250cm9scyBjb21tdW5pY2F0aW9ucyBhdCB0aGUgZXh0ZXJuYWwgYm91bmRhcnkgb2YgdGhlIHN5c3RlbSBhbmQgYXQga2V5IGludGVybmFsIGJvdW5kYXJpZXMgd2l0aGluIHRoZSBzeXN0ZW0uJyxcbiAgJ1NDLjgnOlxuICAgICdUUkFOU01JU1NJT04gQ09ORklERU5USUFMSVRZIEFORCBJTlRFR1JJVFkgLSBUaGUgaW5mb3JtYXRpb24gc3lzdGVtIHByb3RlY3RzIHRoZSBjb25maWRlbnRpYWxpdHkgYW5kIGludGVncml0eSBvZiB0cmFuc21pdHRlZCBpbmZvcm1hdGlvbi4nLFxuICAnU0kuMic6XG4gICAgJ0ZMQVcgUkVNRURJQVRJT04gLSBUaGUgb3JnYW5pemF0aW9uIGlkZW50aWZpZXMsIHJlcG9ydHMsIGFuZCBjb3JyZWN0cyBpbmZvcm1hdGlvbiBzeXN0ZW0gZmxhd3M7IHRlc3RzIHNvZnR3YXJlIGFuZCBmaXJtd2FyZSB1cGRhdGVzIHJlbGF0ZWQgdG8gZmxhdyByZW1lZGlhdGlvbiBmb3IgZWZmZWN0aXZlbmVzcyBhbmQgcG90ZW50aWFsIHNpZGUgZWZmZWN0cyBiZWZvcmUgaW5zdGFsbGF0aW9uOyBpbnN0YWxscyBzZWN1cml0eS1yZWxldmFudCBzb2Z0d2FyZSBhbmQgZmlybXdhcmUgdXBkYXRlcyB3aXRoaW4gb3JnYW5pemF0aW9uZGVmaW5lZCB0aW1lIHBlcmlvZCBvZiB0aGUgcmVsZWFzZSBvZiB0aGUgdXBkYXRlcyBhbmQgIGluY29ycG9yYXRlcyBmbGF3IHJlbWVkaWF0aW9uIGludG8gdGhlIG9yZ2FuaXphdGlvbmFsIGNvbmZpZ3VyYXRpb24gbWFuYWdlbWVudCBwcm9jZXNzLicsXG4gICdTSS4zJzpcbiAgICAnTUFMSUNJT1VTIENPREUgUFJPVEVDVElPTiAtIFRoZSBvcmdhbml6YXRpb24gZW1wbG95cyBtYWxpY2lvdXMgY29kZSBwcm90ZWN0aW9uIG1lY2hhbmlzbXMgYXQgaW5mb3JtYXRpb24gc3lzdGVtIGVudHJ5IGFuZCBleGl0IHBvaW50cyB0byBkZXRlY3QgYW5kIGVyYWRpY2F0ZSBtYWxpY2lvdXMgY29kZSwgdXBkYXRlcyBtYWxpY2lvdXMgY29kZSBwcm90ZWN0aW9uIG1lY2hhbmlzbXMgd2hlbmV2ZXIgbmV3IHJlbGVhc2VzIGFyZSBhdmFpbGFibGUgaW4gYWNjb3JkYW5jZSB3aXRoIG9yZ2FuaXphdGlvbmFsIGNvbmZpZ3VyYXRpb24gbWFuYWdlbWVudCBwb2xpY3kgYW5kIHByb2NlZHVyZXMsIGNvbmZpZ3VyZXMgbWFsaWNpb3VzIGNvZGUgcHJvdGVjdGlvbiBtZWNoYW5pc21zIGFuZCBhZGRyZXNzZXMgdGhlIHJlY2VpcHQgb2YgZmFsc2UgcG9zaXRpdmVzIGR1cmluZyBtYWxpY2lvdXMgY29kZSBkZXRlY3Rpb24gYW5kIGVyYWRpY2F0aW9uIGFuZCB0aGUgcmVzdWx0aW5nIHBvdGVudGlhbCBpbXBhY3Qgb24gdGhlIGF2YWlsYWJpbGl0eSBvZiB0aGUgaW5mb3JtYXRpb24gc3lzdGVtLicsXG4gICdTSS43JzpcbiAgICAnU09GVFdBUkUsIEZJUk1XQVJFLCBBTkQgSU5GT1JNQVRJT04gSU5URUdSSVRZIC0gVGhlIG9yZ2FuaXphdGlvbiBlbXBsb3lzIGludGVncml0eSB2ZXJpZmljYXRpb24gdG9vbHMgdG8gZGV0ZWN0IHVuYXV0aG9yaXplZCBjaGFuZ2VzIHRvIG9yZ2FuaXphdGlvbi1kZWZpbmVkIHNvZnR3YXJlLCBmaXJtd2FyZSwgYW5kIGluZm9ybWF0aW9uLidcbn07XG4iXX0=