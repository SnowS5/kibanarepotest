"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.officeRules = exports.arrayUuidOffice = exports.arrayUserId = exports.arrayTargetOffice = exports.arrayOfficeGroups = exports.arrayLogs = exports.arrayLocationOffice = exports.arrayIp = exports.arrayExtendedPropertiesOffice = exports.arrayDevicePropertiesOffice = exports.arrayDecoderOffice = exports.arrayActorOffice = void 0;

/*
 * Wazuh app - Office365 sample data
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const arrayOfficeGroups = ['office365', 'AzureActiveDirectoryStsLogon'];
exports.arrayOfficeGroups = arrayOfficeGroups;
const arrayLocationOffice = 'office365';
exports.arrayLocationOffice = arrayLocationOffice;
const arrayDecoderOffice = [{
  name: 'json'
}];
exports.arrayDecoderOffice = arrayDecoderOffice;
const arrayUuidOffice = ['a8080009-aa85-4d65-a0f0-74fe0331edce', '4e93c8e3-52c1-4a4e-ab69-9e61ccf6cd00', 'd14aa5cb-b070-42f8-8709-0f8afd942fc0', '92a7e893-0f4a-4635-af0d-83891d4ff9c0', 'ce013f05-a783-4186-9d85-5a14998b6111', '4f686e03-7cf6-44a8-9212-b8a91b128082', 'cc58e817-c6d3-4457-b011-54e881e230ec', '825f9d6e-12c0-4b59-807d-1b41c6e48a3a', 'd36253fb-24a1-481c-a199-f778534ccb5f', '9083369e-679b-4e8b-9249-323a51d5bf9c', '6d872bf8-e462-4de8-9e16-c36761050fb7', 'b9a73c0f-55f2-4e95-9626-1c264d02eac3', 'bbab91ad-bc8a-4c86-9010-3c84b39fde0d', 'b5359092-dad2-4060-b93d-3791e4da0dec', 'e8493b26-c1f9-42eb-9756-dfd363149852', 'ca2044fc-32ca-478b-8b0d-ff6fdd3b1e5a', 'a0995136-91d8-4acf-8449-28c275ffb7e3', 'c3482b5d-b1a9-4f44-8df0-a601e18cf5c3', '49fd4642-cfe5-4170-9488-25d847e3579f', '29f96271-5c1b-47ec-9652-a41d5cb17cb4'];
exports.arrayUuidOffice = arrayUuidOffice;
const arrayDevicePropertiesOffice = [{
  Name: 'BrowserType',
  Value: 'Chrome'
}, {
  Name: 'IsCompliantAndManaged',
  Value: 'False'
}, {
  Name: 'SessionId',
  Value: '2a1fb8c4-ceb6-4fa0-826c-3d43f87de897'
}];
exports.arrayDevicePropertiesOffice = arrayDevicePropertiesOffice;
const arrayIp = ['77.231.182.17', '172.217.204.94', '108.177.13.101', '13.226.52.66', '13.226.52.2', '13.226.52.104', '13.226.52.89', '140.82.113.3'];
exports.arrayIp = arrayIp;
const arrayUserId = ['smith@wazuh.com', 'williams@wazuh.com', 'frank@wazuh.com', 'jones@wazuh.com', 'brown@wazuh.com'];
exports.arrayUserId = arrayUserId;
const arrayTargetOffice = [{
  ID: '797f4846-ba00-4fd7-ba43-dac1f8f63013',
  Type: 0
}];
exports.arrayTargetOffice = arrayTargetOffice;
const arrayActorOffice = [{
  ID: 'a39dd957-d295-4548-b537-2055469bafbb',
  Type: 0
}, {
  ID: 'albe@wazuh.com',
  Type: 5
}];
exports.arrayActorOffice = arrayActorOffice;
const arrayExtendedPropertiesOffice = [{
  Name: 'ResultStatusDetail',
  Value: 'Success'
}, {
  Name: 'UserAgent',
  Value: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36'
}, {
  Name: 'RequestType',
  Value: 'OAuth2:Authorize'
}];
exports.arrayExtendedPropertiesOffice = arrayExtendedPropertiesOffice;
const officeRules = {
  1: {
    data: {
      office365: {
        RecordType: 1,
        Subscription: 'Audit.Exchange'
      }
    },
    rule: {
      level: 3,
      description: 'Office 365: Events from the Exchange admin audit log.',
      id: '91533',
      mail: false,
      firedtimes: 3,
      groups: ['office365', 'ExchangeAdmin', 'hipaa_164.312.b', 'pci_dss_10.2.2', 'pci_dss_10.6.1']
    }
  },
  2: {
    data: {
      office365: {
        RecordType: 2,
        Subscription: 'Audit.Exchange'
      }
    },
    rule: {
      level: 3,
      description: 'Office 365: Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.',
      id: '91534',
      mail: false,
      firedtimes: 3,
      groups: ['office365', 'ExchangeItem', 'hipaa_164.312.b', 'pci_dss_10.6.2']
    }
  },
  4: {
    data: {
      office365: {
        RecordType: 4,
        Subscription: 'Audit.SharePoint'
      }
    },
    rule: {
      level: 3,
      description: 'Office 365: SharePoint events.',
      id: '91536',
      mail: false,
      firedtimes: 3,
      groups: ['office365', 'SharePoint', 'hipaa_164.312.b', 'pci_dss_10.6.2']
    }
  },
  6: {
    data: {
      office365: {
        RecordType: 6,
        Subscription: 'Audit.SharePoint'
      }
    },
    rule: {
      level: 3,
      description: 'Office 365: SharePoint file operation events.',
      id: '91537',
      mail: false,
      firedtimes: 3,
      groups: ['office365', 'SharePointFileOperation', 'hipaa_164.312.b', 'hipaa_164.312.c.1', 'pci_dss_10.6.2', 'pci_dss_11.5']
    }
  },
  8: {
    data: {
      office365: {
        RecordType: 8,
        Subscription: 'Audit.AzureActiveDirectory'
      }
    },
    rule: {
      level: 3,
      description: 'Office 365: Azure Active Directory events.',
      id: '91539',
      mail: false,
      firedtimes: 3,
      groups: ['office365', 'AzureActiveDirectory', 'hipaa_164.312.b', 'pci_dss_10.6.2']
    }
  },
  14: {
    data: {
      office365: {
        RecordType: 14,
        Subscription: 'Audit.SharePoint'
      }
    },
    rule: {
      level: 3,
      description: 'Office 365: SharePoint sharing events.',
      id: '91544',
      mail: false,
      firedtimes: 3,
      groups: ['office365', 'SharePoint', 'hipaa_164.312.b', 'pci_dss_10.6.2']
    }
  },
  15: {
    data: {
      office365: {
        RecordType: 15,
        Subscription: 'Audit.AzureActiveDirectory'
      }
    },
    rule: {
      level: 3,
      description: 'Office 365: Secure Token Service (STS) logon events in Azure Active Directory.',
      id: '91545',
      mail: false,
      firedtimes: 3,
      groups: ['office365', 'AzureActiveDirectoryStsLogon', 'hipaa_164.312.a.2.I,hipaa_164.312.b', 'hipaa_164.312.d', 'hipaa_164.312.e.2.II', 'pci_dss_8.3,pci_dss_10.6.1']
    }
  },
  18: {
    data: {
      office365: {
        RecordType: 18,
        Subscription: 'Audit.General'
      }
    },
    rule: {
      level: 5,
      description: 'Office 365: Admin actions from the Security and Compliance Center.',
      id: '91548',
      mail: false,
      firedtimes: 3,
      groups: ['office365', 'SecurityComplianceCenterEOPCmdlet', 'hipaa_164.312.b', 'pci_dss_10.2.2', 'pci_dss_10.6.1']
    }
  },
  36: {
    data: {
      office365: {
        RecordType: 36,
        Subscription: 'Audit.SharePoint'
      }
    },
    rule: {
      level: 3,
      description: 'Office 365: SharePoint List events.',
      id: '91564',
      mail: false,
      firedtimes: 3,
      groups: ['office365', 'SharePointListOperation', 'hipaa_164.312.b', 'pci_dss_10.6.2']
    }
  },
  52: {
    data: {
      office365: {
        RecordType: 52,
        Subscription: 'Audit.General'
      }
    },
    rule: {
      level: 3,
      description: 'Office 365: Data Insights REST API events.',
      id: '91580',
      mail: false,
      firedtimes: 4,
      groups: ['office365', 'DataInsightsRestApiAudit', 'hipaa_164.312.b', 'pci_dss_10.6.2']
    }
  }
};
exports.officeRules = officeRules;
const arrayLogs = [{
  Id: '35ab8b89-cfea-4214-5249-08d91a06e537',
  Operation: 'SearchDataInsightsSubscription',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 52,
  UserKey: 'fake@email.not',
  UserType: 5,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  UserId: 'fake@email.not',
  AadAppId: '80ccca67-54bd-44ab-8625-4b79c4dc7775',
  DataType: 'DataInsightsSubscription',
  DatabaseType: 'Directory',
  RelativeUrl: '/DataInsights/DataInsightsService.svc/Find/DataInsightsSubscription?tenantid=0fea4e03-8146-453b-b889-54b4bd11565b',
  ResultCount: '1'
}, {
  Id: '27ee2e95-6f55-4723-f91d-08d91a26b9a4',
  Operation: 'SearchAlert',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 52,
  UserKey: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
  UserType: 0,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  UserId: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
  AadAppId: 'fc780465-2017-40d4-a0c5-307022471b92',
  DataType: 'Alert',
  DatabaseType: 'DataInsights',
  RelativeUrl: '/DataInsights/DataInsightsService.svc/Find/Alert?tenantid=0fea4e03-8146-453b-b889-54b4bd11565b&PageSize=100&Filter=StartDate+eq+2021-04-18T17%3a59%3a40.8820655Z+and+EndDate+eq+2021-05-18T17%3a59%3a40.8820655Z+and+AlertCategory+any+1%2c3%2c7%2c5%2c4+and+AlertSource+eq+%27Office+365+Security+%26+Compliance%27',
  ResultCount: '0'
}, {
  CreationTime: '2021-05-18T17:59:52',
  Id: '7d3a9d35-6c04-4f02-e8fe-08d91a26bc79',
  Operation: 'SearchAlertAggregate',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 52,
  UserKey: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
  UserType: 0,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  UserId: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
  AadAppId: 'fc780465-2017-40d4-a0c5-307022471b92',
  DataType: 'AlertAggregate',
  DatabaseType: 'DataInsights',
  RelativeUrl: '/DataInsights/DataInsightsService.svc/Find/AlertAggregate?tenantid=0fea4e03-8146-453b-b889-54b4bd11565b&PageSize=540&Filter=StartDate+eq+2021-04-18T17%3a59%3a48.3504050Z+and+EndDate+eq+2021-05-18T17%3a59%3a48.3504050Z+and+AlertCategory+any+1%2c3%2c7%2c5%2c4+and+AlertSource+eq+%27Office+365+Security+%26+Compliance%27',
  ResultCount: '0'
}, {
  CreationTime: '2021-05-18T17:59:46',
  Id: 'eb9775cb-59f7-42ea-3ee0-08d91a26b92b',
  Operation: 'ValidaterbacAccessCheck',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 52,
  UserKey: 'fake@email.not',
  UserType: 5,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  UserId: 'fake@email.not',
  AadAppId: 'd6fdaa33-e821-4211-83d0-cf74736489e1',
  DataType: 'rbacAccessCheck',
  RelativeUrl: '/DataInsights/DataInsightsService.svc/validate/rbacAccessCheck?tenantid=0fea4e03-8146-453b-b889-54b4bd11565b',
  ResultCount: '0'
}, {
  CreationTime: '2021-05-18T14:12:53',
  Id: 'c0eada1b-52b2-450d-84df-6d461420d621',
  Operation: 'Get-RetentionCompliancePolicy',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 18,
  ResultStatus: 'Success',
  UserKey: 'fake@email.not',
  UserType: 2,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  ObjectId: '',
  UserId: 'fake@email.not',
  SecurityComplianceCenterEventType: 0,
  ClientApplication: 'EMC',
  CmdletVersion: '...',
  EffectiveOrganization: 'wazuh.testytest.com',
  NonPIIParameters: '',
  Parameters: '',
  StartTime: '2021-05-18T14:12:53',
  UserServicePlan: ''
}, {
  CreationTime: '2021-05-18T15:52:26',
  Id: '45a0d7c4-de73-466a-8e6c-c25f9c035714',
  Operation: 'Get-SupervisoryReviewPolicyV2',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 18,
  ResultStatus: 'Success',
  UserKey: 'fake@email.not',
  UserType: 2,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  ObjectId: '',
  UserId: 'fake@email.not',
  SecurityComplianceCenterEventType: 0,
  ClientApplication: 'EMC',
  CmdletVersion: '...',
  EffectiveOrganization: 'wazuh.testytest.com',
  NonPIIParameters: '',
  Parameters: '',
  StartTime: '2021-05-18T15:52:26',
  UserServicePlan: ''
}, {
  CreationTime: '2021-05-18T15:52:31',
  Id: 'f9912868-b431-435c-8337-0fc3b4370815',
  Operation: 'Get-SupervisoryReviewReport',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 18,
  ResultStatus: 'Success',
  UserKey: 'fake@email.not',
  UserType: 2,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  ObjectId: '',
  UserId: 'fake@email.not',
  SecurityComplianceCenterEventType: 0,
  ClientApplication: 'EMC',
  CmdletVersion: '...',
  EffectiveOrganization: 'wazuh.testytest.com',
  NonPIIParameters: '-StartDate "<SNIP-PII>" -EndDate "<SNIP-PII>" -PageSize "<SNIP-PII>" -Page "<SNIP-PII>"',
  Parameters: '-StartDate "5/12/2021 12:00:00 AM" -EndDate "5/18/2021 11:59:59 PM" -PageSize "300" -Page "1"',
  StartTime: '2021-05-18T15:52:31',
  UserServicePlan: ''
}, {
  CreationTime: '2021-05-18T15:52:30',
  Id: 'dcecd87a-3061-4dea-9bff-4fbfc23ca328',
  Operation: 'Get-SupervisoryReviewOverallProgressReport',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 18,
  ResultStatus: 'Success',
  UserKey: 'fake@email.not',
  UserType: 2,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  ObjectId: '',
  UserId: 'fake@email.not',
  SecurityComplianceCenterEventType: 0,
  ClientApplication: 'EMC',
  CmdletVersion: '...',
  EffectiveOrganization: 'wazuh.testytest.com',
  NonPIIParameters: '',
  Parameters: '',
  StartTime: '2021-05-18T15:52:30',
  UserServicePlan: ''
}, {
  CreationTime: '2021-05-18T15:52:30',
  Id: '5641d062-f279-4ca4-9577-50d7ecbfeedb',
  Operation: 'Get-SupervisoryReviewTopCasesReport',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 18,
  ResultStatus: 'Success',
  UserKey: 'fake@email.not',
  UserType: 2,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  ObjectId: '',
  UserId: 'fake@email.not',
  SecurityComplianceCenterEventType: 0,
  ClientApplication: 'EMC',
  CmdletVersion: '...',
  EffectiveOrganization: 'wazuh.testytest.com',
  NonPIIParameters: '',
  Parameters: '',
  StartTime: '2021-05-18T15:52:30',
  UserServicePlan: ''
}, {
  CreationTime: '2021-05-18T17:50:15',
  Id: '8c7c9f81-68e9-452b-a22d-1333eb9cd647',
  Operation: 'Get-ComplianceSearchAction',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 18,
  ResultStatus: 'Success',
  UserKey: 'fake@email.not',
  UserType: 2,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  ObjectId: '',
  UserId: 'fake@email.not',
  SecurityComplianceCenterEventType: 0,
  ClientApplication: 'EMC',
  CmdletVersion: '...',
  EffectiveOrganization: 'wazuh.testytest.com',
  NonPIIParameters: '-Export "<SNIP-PII>"',
  Parameters: '-Export "True"',
  StartTime: '2021-05-18T17:50:15',
  UserServicePlan: ''
}, {
  CreationTime: '2021-05-18T17:50:12',
  Id: '4692201f-8101-455e-b89d-6727ef75c223',
  Operation: 'Get-ComplianceTag',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 18,
  ResultStatus: 'Success',
  UserKey: 'fake@email.not',
  UserType: 2,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  ObjectId: '',
  UserId: 'fake@email.not',
  SecurityComplianceCenterEventType: 0,
  ClientApplication: 'EMC',
  CmdletVersion: '...',
  EffectiveOrganization: 'wazuh.testytest.com',
  NonPIIParameters: '-IncludingLabelState "<SNIP-PII>"',
  Parameters: '-IncludingLabelState "True"',
  StartTime: '2021-05-18T17:50:12',
  UserServicePlan: ''
}, {
  CreationTime: '2021-05-18T17:50:12',
  Id: '7d41f1f2-587c-492f-b6ff-2f9d1a519c60',
  Operation: 'Get-ComplianceSearch',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 18,
  ResultStatus: 'Success',
  UserKey: 'fake@email.not',
  UserType: 2,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  ObjectId: '',
  UserId: 'fake@email.not',
  SecurityComplianceCenterEventType: 0,
  ClientApplication: 'EMC',
  CmdletVersion: '...',
  EffectiveOrganization: 'wazuh.testytest.com',
  NonPIIParameters: '-ResultSize "Unlimited"',
  Parameters: '-ResultSize "Unlimited"',
  StartTime: '2021-05-18T17:50:12',
  UserServicePlan: ''
}, {
  CreationTime: '2021-05-18T17:59:45',
  Id: 'ebcfc2bf-8799-413c-add4-6c2b53cb68e7',
  Operation: 'Get-DlpSensitiveInformationType',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 18,
  ResultStatus: 'Success',
  UserKey: 'fake@email.not',
  UserType: 0,
  Version: 1,
  Workload: 'SecurityComplianceCenter',
  ObjectId: '',
  UserId: 'fake@email.not',
  SecurityComplianceCenterEventType: 0,
  ClientApplication: '',
  CmdletVersion: '...',
  EffectiveOrganization: 'wazuh.testytest.com',
  NonPIIParameters: '-Organization "0fea4e03-8146-453b-b889-54b4bd11565b"',
  Parameters: '-Organization "0fea4e03-8146-453b-b889-54b4bd11565b"',
  StartTime: '2021-05-18T17:59:45',
  UserServicePlan: ''
}, {
  CreationTime: '2021-05-18T14:11:41',
  Id: '7aeca226-b3e7-4033-9a7f-d067622e8d00',
  Operation: 'UserLoggedIn',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 15,
  ResultStatus: 'Success',
  UserKey: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
  UserType: 0,
  Version: 1,
  Workload: 'AzureActiveDirectory',
  ClientIP: '190.16.9.176',
  ObjectId: '5f09333a-842c-47da-a157-57da27fcbca5',
  UserId: 'fake@email.not',
  AzureActiveDirectoryEventType: 1,
  ExtendedProperties: [{
    Name: 'ResultStatusDetail',
    Value: 'Redirect'
  }, {
    Name: 'UserAgent',
    Value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
  }, {
    Name: 'RequestType',
    Value: 'OAuth2:Authorize'
  }],
  ModifiedProperties: [],
  Actor: [{
    ID: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
    Type: 0
  }, {
    ID: 'fake@email.not',
    Type: 5
  }],
  ActorContextId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  ActorIpAddress: '190.16.9.176',
  InterSystemsId: 'a3798792-fef1-4b53-bd44-bbbd94cf0e5c',
  IntraSystemId: '7aeca226-b3e7-4033-9a7f-d067622e8d00',
  SupportTicketId: '',
  Target: [{
    ID: '5f09333a-842c-47da-a157-57da27fcbca5',
    Type: 0
  }],
  TargetContextId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  ApplicationId: '89bee1f7-5e6e-4d8a-9f3d-ecd601259da7',
  DeviceProperties: [{
    Name: 'OS',
    Value: 'Windows 10'
  }, {
    Name: 'BrowserType',
    Value: 'Chrome'
  }, {
    Name: 'IsCompliantAndManaged',
    Value: 'False'
  }, {
    Name: 'SessionId',
    Value: '714c4935-a22d-400d-8563-fbbd8bfc2301'
  }],
  ErrorNumber: '0'
}, {
  CreationTime: '2021-05-18T17:49:11',
  Id: '4e621563-394f-42a9-8a8a-8549e1ffa771',
  Operation: 'Add service principal.',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 8,
  ResultStatus: 'Success',
  UserKey: 'Not Available',
  UserType: 4,
  Version: 1,
  Workload: 'AzureActiveDirectory',
  ObjectId: 'f738ef14-47dc-4564-b53b-45069484ccc7',
  UserId: 'ServicePrincipal_4bf80788-0ec4-481a-ae7b-b71647bf3b57',
  AzureActiveDirectoryEventType: 1,
  ExtendedProperties: [{
    Name: 'additionalDetails',
    Value: '{}'
  }, {
    Name: 'extendedAuditEventCategory',
    Value: 'ServicePrincipal'
  }],
  ModifiedProperties: [{
    Name: 'AccountEnabled',
    NewValue: '[\r\n  true\r\n]',
    OldValue: '[]'
  }, {
    Name: 'AppPrincipalId',
    NewValue: '[\r\n  "f738ef14-47dc-4564-b53b-45069484ccc7"\r\n]',
    OldValue: '[]'
  }, {
    Name: 'DisplayName',
    NewValue: '[\r\n  "Marketplace Api"\r\n]',
    OldValue: '[]'
  }, {
    Name: 'ServicePrincipalName',
    NewValue: '[\r\n  "f738ef14-47dc-4564-b53b-45069484ccc7"\r\n]',
    OldValue: '[]'
  }, {
    Name: 'Credential',
    NewValue: '[\r\n  {\r\n    "CredentialType": 2,\r\n    "KeyStoreId": "291154f0-a9f5-45bb-87be-9c8ee5b6d62c",\r\n    "KeyGroupId": "1c5aa04b-dea5-4284-9908-47edd1e12d13"\r\n  }\r\n]',
    OldValue: '[]'
  }, {
    Name: 'Included Updated Properties',
    NewValue: 'AccountEnabled, AppPrincipalId, DisplayName, ServicePrincipalName, Credential',
    OldValue: ''
  }, {
    Name: 'TargetId.ServicePrincipalNames',
    NewValue: 'f738ef14-47dc-4564-b53b-45069484ccc7',
    OldValue: ''
  }],
  Actor: [{
    ID: 'Windows Azure Service Management API',
    Type: 1
  }, {
    ID: '797f4846-ba00-4fd7-ba43-dac1f8f63013',
    Type: 2
  }, {
    ID: 'ServicePrincipal_4bf80788-0ec4-481a-ae7b-b71647bf3b57',
    Type: 2
  }, {
    ID: '4bf80788-0ec4-481a-ae7b-b71647bf3b57',
    Type: 2
  }, {
    ID: 'ServicePrincipal',
    Type: 2
  }],
  ActorContextId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  InterSystemsId: '9cfba3bb-b478-44aa-a140-465ee7f29274',
  IntraSystemId: '21051805-2413-594a-ab5d-006014005348',
  SupportTicketId: '',
  Target: [{
    ID: 'ServicePrincipal_f6d2eabc-d020-4643-80a8-2b92b163d1de',
    Type: 2
  }, {
    ID: 'f6d2eabc-d020-4643-80a8-2b92b163d1de',
    Type: 2
  }, {
    ID: 'ServicePrincipal',
    Type: 2
  }, {
    ID: 'Marketplace Api',
    Type: 1
  }, {
    ID: 'f738ef14-47dc-4564-b53b-45069484ccc7',
    Type: 2
  }, {
    ID: 'f738ef14-47dc-4564-b53b-45069484ccc7',
    Type: 4
  }],
  TargetContextId: '0fea4e03-8146-453b-b889-54b4bd11565b'
}, {
  CreationTime: '2021-05-18T21:42:25',
  Id: 'af4e552f-0bca-4b02-92c9-4bd430f24f75',
  Operation: 'Change user license.',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 8,
  ResultStatus: 'Success',
  UserKey: '100320014080D3AD@wazuh.com',
  UserType: 0,
  Version: 1,
  Workload: 'AzureActiveDirectory',
  ObjectId: 'fake@email.not',
  UserId: 'fake@email.not',
  AzureActiveDirectoryEventType: 1,
  ExtendedProperties: [{
    Name: 'additionalDetails',
    Value: '{}'
  }, {
    Name: 'extendedAuditEventCategory',
    Value: 'User'
  }],
  ModifiedProperties: [],
  Actor: [{
    ID: 'fake@email.not',
    Type: 5
  }, {
    ID: '100320014080D3AD',
    Type: 3
  }, {
    ID: 'User_910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
    Type: 2
  }, {
    ID: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
    Type: 2
  }, {
    ID: 'User',
    Type: 2
  }],
  ActorContextId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  InterSystemsId: '1fd09d6b-54d3-4a58-acfe-71cc2c429d97',
  IntraSystemId: '0a8ae201-e404-4f6f-99db-a3c92a5bd022',
  SupportTicketId: '',
  Target: [{
    ID: 'User_910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
    Type: 2
  }, {
    ID: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
    Type: 2
  }, {
    ID: 'User',
    Type: 2
  }, {
    ID: 'fake@email.not',
    Type: 5
  }, {
    ID: '100320014080D3AD',
    Type: 3
  }],
  TargetContextId: '0fea4e03-8146-453b-b889-54b4bd11565b'
}, {
  CreationTime: '2021-05-18T21:42:25',
  Id: 'b27eab84-1ef7-4372-bc68-7213af8ab3fb',
  Operation: 'Update user.',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 8,
  ResultStatus: 'Success',
  UserKey: '100320014080D3AD@wazuh.com',
  UserType: 0,
  Version: 1,
  Workload: 'AzureActiveDirectory',
  ObjectId: 'fake@email.not',
  UserId: 'fake@email.not',
  AzureActiveDirectoryEventType: 1,
  ExtendedProperties: [{
    Name: 'additionalDetails',
    Value: '{"UserType":"Member"}'
  }, {
    Name: 'extendedAuditEventCategory',
    Value: 'User'
  }],
  ModifiedProperties: [{
    Name: 'AssignedLicense',
    NewValue: '[\r\n  "[SkuName=POWER_BI_STANDARD, AccountId=0fea4e03-8146-453b-b889-54b4bd11565b, SkuId=a403ebcc-fae0-4ca2-8c8c-7a907fd6c235, DisabledPlans=[]]"\r\n]',
    OldValue: '[]'
  }, {
    Name: 'AssignedPlan',
    NewValue: '[\r\n  {\r\n    "SubscribedPlanId": "c976d07f-fd0f-49eb-bdc2-26c17481e1c5",\r\n    "ServiceInstance": "AzureAnalysis/SDF",\r\n    "CapabilityStatus": 0,\r\n    "AssignedTimestamp": "2021-05-18T21:42:25.3894164Z",\r\n    "InitialState": null,\r\n    "Capability": null,\r\n    "ServicePlanId": "2049e525-b859-401b-b2a0-e0a31c4b1fe4"\r\n  }\r\n]',
    OldValue: '[]'
  }, {
    Name: 'Included Updated Properties',
    NewValue: 'AssignedLicense, AssignedPlan',
    OldValue: ''
  }, {
    Name: 'TargetId.UserType',
    NewValue: 'Member',
    OldValue: ''
  }],
  Actor: [{
    ID: 'fake@email.not',
    Type: 5
  }, {
    ID: '100320014080D3AD',
    Type: 3
  }, {
    ID: 'User_910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
    Type: 2
  }, {
    ID: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
    Type: 2
  }, {
    ID: 'User',
    Type: 2
  }],
  ActorContextId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  InterSystemsId: '1fd09d6b-54d3-4a58-acfe-71cc2c429d97',
  IntraSystemId: '0a8ae201-e404-4f6f-99db-a3c92a5bd022',
  SupportTicketId: '',
  Target: [{
    ID: 'User_910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
    Type: 2
  }, {
    ID: '910ed5ca-4ecf-414c-a1be-d53511bfe1a5',
    Type: 2
  }, {
    ID: 'User',
    Type: 2
  }, {
    ID: 'fake@email.not',
    Type: 5
  }, {
    ID: '100320014080D3AD',
    Type: 3
  }],
  TargetContextId: '0fea4e03-8146-453b-b889-54b4bd11565b'
}, {
  CreationTime: '2021-05-20T17:43:00',
  Id: '8c3d0215-66f0-41b0-3205-08d91bb6b63c',
  Operation: 'SharingPolicyChanged',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 4,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'OneDrive',
  ClientIP: '20.190.157.27',
  ObjectId: 'https://wazuh-my.sharepoint.com/personal/tomas_turina_wazuh_com',
  UserId: 'fake@email.not',
  CorrelationId: 'fd9ac79d-1100-48aa-92c5-40a73a1d443f',
  EventSource: 'SharePoint',
  ItemType: 'Site',
  Site: 'f49feae4-033d-4028-97d1-3acd55341f69',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  ModifiedProperties: [{
    Name: 'ShareUsingAnonymousLinks',
    NewValue: 'Enabled',
    OldValue: 'Disabled'
  }]
}, {
  CreationTime: '2021-05-20T17:43:00',
  Id: '35a1b515-2a0e-4bd6-d0a3-08d91bb6b639',
  Operation: 'SiteCollectionCreated',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 4,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'OneDrive',
  ClientIP: '20.190.157.27',
  ObjectId: 'https://wazuh-my.sharepoint.com/personal/tomas_turina_wazuh_com',
  UserId: 'fake@email.not',
  CorrelationId: 'fd9ac79d-1100-48aa-92c5-40a73a1d443f',
  EventSource: 'SharePoint',
  ItemType: 'Site',
  Site: 'f49feae4-033d-4028-97d1-3acd55341f69',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  EventData: '<SiteCreationSource>API</SiteCreationSource><TenantSettings.ShowCreateSiteCommand>True</TenantSettings.ShowCreateSiteCommand><TenantSettings.UseCustomSiteCreationForm>False</TenantSettings.UseCustomSiteCreationForm>'
}, {
  CreationTime: '2021-05-20T17:43:00',
  Id: '344f9139-f437-4290-9566-08d91bb6b61f',
  Operation: 'SiteCollectionAdminRemoved',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 14,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'OneDrive',
  ClientIP: '20.190.157.27',
  ObjectId: 'https://wazuh-my.sharepoint.com/personal/tomas_turina_wazuh_com',
  UserId: 'fake@email.not',
  CorrelationId: 'fd9ac79d-1100-48aa-92c5-40a73a1d443f',
  EventSource: 'SharePoint',
  ItemType: 'Web',
  Site: 'f49feae4-033d-4028-97d1-3acd55341f69',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: 'a9d15b23-6ac9-43c5-af3c-b4a0916631c1',
  ModifiedProperties: [{
    Name: 'SiteAdmin',
    NewValue: '',
    OldValue: ''
  }],
  TargetUserOrGroupType: 'Member',
  SiteUrl: 'https://wazuh-my.sharepoint.com/personal/tomas_turina_wazuh_com',
  TargetUserOrGroupName: 'SHAREPOINT\\system'
}, {
  CreationTime: '2021-05-20T17:43:00',
  Id: 'd36e4b4d-1e8b-4634-6dd8-08d91bb6b618',
  Operation: 'SiteCollectionAdminAdded',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 14,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'OneDrive',
  ClientIP: '20.190.157.27',
  ObjectId: 'https://wazuh-my.sharepoint.com/personal/tomas_turina_wazuh_com',
  UserId: 'fake@email.not',
  CorrelationId: 'fd9ac79d-1100-48aa-92c5-40a73a1d443f',
  EventSource: 'SharePoint',
  ItemType: 'Web',
  Site: 'f49feae4-033d-4028-97d1-3acd55341f69',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: 'a9d15b23-6ac9-43c5-af3c-b4a0916631c1',
  ModifiedProperties: [{
    Name: 'SiteAdmin',
    NewValue: 'fake@email.not',
    OldValue: ''
  }],
  TargetUserOrGroupType: 'Member',
  SiteUrl: 'https://wazuh-my.sharepoint.com/personal/tomas_turina_wazuh_com',
  TargetUserOrGroupName: 'fake@email.not'
}, {
  CreationTime: '2021-05-20T17:43:22',
  Id: '0d6a62d3-e4bd-44ee-ce8d-08d91bb6c392',
  Operation: 'PageViewed',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 4,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/_layouts/15/CreateGroup.aspx',
  UserId: 'fake@email.not',
  CorrelationId: 'ccd0c99f-309b-2000-df13-3fcca9a8c8e1',
  CustomUniqueId: true,
  EventSource: 'SharePoint',
  ItemType: 'Page',
  ListItemUniqueId: '59a8433d-9bb8-cfef-65b7-ef35de00c8f6',
  Site: 'f7fbb805-5f6b-4950-b681-2365eb46081f',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '3b56db49-60e3-410e-acbd-d8765467388a'
}, {
  CreationTime: '2021-05-20T17:45:57',
  Id: '18bb351b-49e1-47df-8f4d-08d91bb71ffd',
  Operation: 'AddedToGroup',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 14,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint',
  UserId: 'fake@email.not',
  CorrelationId: 'f1d0c99f-3094-2000-da82-454f034ca629',
  EventSource: 'SharePoint',
  ItemType: 'Web',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7',
  EventData: '<Group>Site Owners</Group>',
  TargetUserOrGroupType: 'Member',
  SiteUrl: 'https://wazuh.sharepoint.com/sites/TestSharePoint',
  TargetUserOrGroupName: 'SHAREPOINT\\system'
}, {
  CreationTime: '2021-05-20T17:46:26',
  Id: '29bde84a-d3ec-4388-4600-08d91bb730bc',
  Operation: 'FileAccessed',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 6,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint/Shared Documents/Forms/AllItems.aspx',
  UserId: 'fake@email.not',
  CorrelationId: 'f9d0c99f-b04f-2000-da82-4bb2abf6168f',
  EventSource: 'SharePoint',
  ItemType: 'File',
  ListId: 'fd2ebaf0-900b-4dff-8fc2-d348be51e677',
  ListItemUniqueId: '3c9d8943-846e-41f3-a647-72a5e4e3decf',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7',
  SourceFileExtension: 'aspx',
  SiteUrl: 'https://wazuh.sharepoint.com/sites/TestSharePoint/',
  SourceFileName: 'AllItems.aspx',
  SourceRelativeUrl: 'Shared Documents/Forms'
}, {
  CreationTime: '2021-05-20T17:46:25',
  Id: '087e5b68-fc3f-4e01-1efc-08d91bb730b5',
  Operation: 'ListViewed',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 36,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint/fd2ebaf0-900b-4dff-8fc2-d348be51e677',
  UserId: 'fake@email.not',
  CorrelationId: 'f9d0c99f-b04f-2000-da82-4bb2abf6168f',
  DoNotDistributeEvent: true,
  EventSource: 'SharePoint',
  ItemType: 'List',
  ListId: 'fd2ebaf0-900b-4dff-8fc2-d348be51e677',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7',
  CustomizedDoclib: false,
  FromApp: true,
  IsDocLib: true,
  ItemCount: 0,
  ListBaseTemplateType: '101',
  ListBaseType: 'DocumentLibrary',
  ListColor: '',
  ListIcon: '',
  Source: 'Unknown',
  TemplateTypeId: '',
  ListTitle: 'fd2ebaf0-900b-4dff-8fc2-d348be51e677'
}, {
  CreationTime: '2021-05-20T17:52:29',
  Id: '41225487-31c1-4e24-b8b0-08d91bb8094c',
  Operation: 'PagePrefetched',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 4,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint',
  UserId: 'fake@email.not',
  CorrelationId: '52d1c99f-3000-2000-df13-3ab1e8fb9f92',
  CustomUniqueId: false,
  EventSource: 'SharePoint',
  ItemType: 'Page',
  ListId: 'e4c9ce2e-d8c2-468e-baf5-f362f8c2f2f3',
  ListItemUniqueId: '36db3168-c1b2-44e9-9ffd-e9a8e04bb2f5',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7'
}, {
  CreationTime: '2021-05-20T17:51:49',
  Id: 'd930cc5c-2658-45df-6361-08d91bb7f179',
  Operation: 'FileCheckedOut',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 6,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint/SitePages/Home.aspx',
  UserId: 'fake@email.not',
  CorrelationId: '48d1c99f-f03c-2000-df13-38983a6608f8',
  EventSource: 'SharePoint',
  ItemType: 'File',
  ListId: 'e4c9ce2e-d8c2-468e-baf5-f362f8c2f2f3',
  ListItemUniqueId: '36db3168-c1b2-44e9-9ffd-e9a8e04bb2f5',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7',
  HighPriorityMediaProcessing: false,
  SourceFileExtension: 'aspx',
  SiteUrl: 'https://wazuh.sharepoint.com/sites/TestSharePoint/',
  SourceFileName: 'Home.aspx',
  SourceRelativeUrl: 'SitePages'
}, {
  CreationTime: '2021-05-20T17:51:51',
  Id: '89d76362-e493-4c20-3b69-08d91bb7f288',
  Operation: 'ListUpdated',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 36,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint/e4c9ce2e-d8c2-468e-baf5-f362f8c2f2f3',
  UserId: 'fake@email.not',
  CorrelationId: '48d1c99f-f0a8-2000-da82-41be3f973267',
  DoNotDistributeEvent: true,
  EventSource: 'SharePoint',
  ItemType: 'List',
  ListId: 'e4c9ce2e-d8c2-468e-baf5-f362f8c2f2f3',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7',
  CustomizedDoclib: false,
  FromApp: false,
  IsDocLib: true,
  ItemCount: 1,
  ListBaseTemplateType: '119',
  ListBaseType: 'DocumentLibrary',
  ListColor: '',
  ListIcon: '',
  Source: 'Unknown',
  TemplateTypeId: '',
  ListTitle: 'e4c9ce2e-d8c2-468e-baf5-f362f8c2f2f3'
}, {
  CreationTime: '2021-05-20T17:52:36',
  Id: '7a91dd8c-560b-4fbe-2585-08d91bb80d46',
  Operation: 'ClientViewSignaled',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 4,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint/SitePages/Home.aspx',
  UserId: 'fake@email.not',
  CorrelationId: '53d1c99f-b0aa-2000-df13-3efea9e41071',
  CustomUniqueId: false,
  EventSource: 'SharePoint',
  ItemType: 'Page',
  ListId: 'e4c9ce2e-d8c2-468e-baf5-f362f8c2f2f3',
  ListItemUniqueId: '36db3168-c1b2-44e9-9ffd-e9a8e04bb2f5',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7'
}, {
  CreationTime: '2021-05-20T17:53:37',
  Id: '9695afcd-19ff-491f-a6ee-08d91bb831d1',
  Operation: 'FileModified',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 6,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint/SitePages/Home.aspx',
  UserId: 'fake@email.not',
  CorrelationId: '62d1c99f-d09c-2000-df13-37ddf480e717',
  DoNotDistributeEvent: true,
  EventSource: 'SharePoint',
  ItemType: 'File',
  ListId: 'e4c9ce2e-d8c2-468e-baf5-f362f8c2f2f3',
  ListItemUniqueId: '36db3168-c1b2-44e9-9ffd-e9a8e04bb2f5',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7',
  SourceFileExtension: 'aspx',
  SiteUrl: 'https://wazuh.sharepoint.com/sites/TestSharePoint/',
  SourceFileName: 'Home.aspx',
  SourceRelativeUrl: 'SitePages'
}, {
  CreationTime: '2021-05-20T17:57:03',
  Id: '551fd7d5-bac1-4bb4-11d2-08d91bb8ac9e',
  Operation: 'FileAccessedExtended',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 6,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint/Shared Documents/Forms/AllItems.aspx',
  UserId: 'fake@email.not',
  CorrelationId: '94d1c99f-20eb-2000-df13-35746d02911e',
  EventSource: 'SharePoint',
  ItemType: 'File',
  ListId: 'fd2ebaf0-900b-4dff-8fc2-d348be51e677',
  ListItemUniqueId: '3c9d8943-846e-41f3-a647-72a5e4e3decf',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7',
  SourceFileExtension: 'aspx',
  SiteUrl: 'https://wazuh.sharepoint.com/sites/TestSharePoint/',
  SourceFileName: 'AllItems.aspx',
  SourceRelativeUrl: 'Shared Documents/Forms'
}, {
  CreationTime: '2021-05-20T17:59:55',
  Id: 'eb1f0911-9bed-4f15-10e5-08d91bb91372',
  Operation: 'SiteDeleted',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 6,
  UserKey: 'S-1-0-0',
  UserType: 4,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint',
  UserId: 'AAD to SharePoint Sync',
  CorrelationId: 'bed1c99f-20ee-2000-df13-306cb6803c92',
  EventSource: 'SharePoint',
  ItemType: 'Web',
  ListItemUniqueId: '00000000-0000-0000-0000-000000000000',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: '',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7',
  DestinationFileExtension: '',
  SourceFileExtension: '',
  DestinationFileName: 'TestSharePoint',
  DestinationRelativeUrl: '../../https://wazuh.sharepoint.com/sites',
  SiteUrl: 'https://wazuh.sharepoint.com/sites/TestSharePoint/',
  SourceFileName: 'TestSharePoint',
  SourceRelativeUrl: '..'
}, {
  CreationTime: '2021-05-20T17:59:11',
  Id: '0d20a3e1-e9cb-436c-799f-08d91bb8f92f',
  Operation: 'PageViewedExtended',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 4,
  UserKey: 'i:0h.f|membership|100320014080d3ad@live.com',
  UserType: 0,
  Version: 1,
  Workload: 'SharePoint',
  ClientIP: '190.16.9.176',
  ObjectId: 'https://wazuh.sharepoint.com/sites/TestSharePoint/_layouts/15/online/handlers/SpoSuiteLinks.ashx',
  UserId: 'fake@email.not',
  CorrelationId: 'b4d1c99f-0043-2000-da82-41b63e1d91f4',
  EventSource: 'SharePoint',
  ItemType: 'Page',
  Site: 'dd58ef08-faea-4cb5-847a-35bb5c01e757',
  UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
  WebId: '00c32555-e0d8-425f-9fbd-ef5539bfecf7'
}, {
  CreationTime: '2021-05-20T17:44:27',
  Id: '30ef2f70-a12d-4b31-1e70-08d91bb6ea2e',
  Operation: 'Set-Mailbox',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 1,
  ResultStatus: 'True',
  UserKey: 'SpoolsProvisioning-ApplicationAccount@eurprd04.prod.outlook.com',
  UserType: 3,
  Version: 1,
  Workload: 'Exchange',
  ClientIP: '52.233.237.141:40638',
  ObjectId: 'EURPR04A010.prod.outlook.com/Microsoft Exchange Hosted Organizations/wazuh.testytest.com/tomas.turina',
  UserId: 'SpoolsProvisioning-ApplicationAccount@eurprd04.prod.outlook.com',
  AppId: '61109738-7d2b-4a0b-9fe3-660b1ff83505',
  ClientAppId: '',
  ExternalAccess: true,
  OrganizationName: 'wazuh.testytest.com',
  OriginatingServer: 'AM9PR04MB8986 (15.20.4150.023)',
  Parameters: [{
    Name: 'Identity',
    Value: 'MGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViXGJkYmI4MjM2LTBmNDgtNGZjNi05Zjc3LTkxNGNkY2MwMmIzYw2'
  }, {
    Name: 'ResourceEmailAddresses',
    Value: 'True'
  }, {
    Name: 'BypassLiveId',
    Value: 'True'
  }, {
    Name: 'Force',
    Value: 'True'
  }, {
    Name: 'DomainController',
    Value: 'HE1PR04A010DC03.EURPR04A010.prod.outlook.com'
  }, {
    Name: 'EmailAddresses',
    Value: 'SIP:fake@email.not;SMTP:fake@email.not;SPO:SPO_f49feae4-033d-4028-97d1-3acd55341f69@SPO_0fea4e03-8146-453b-b889-54b4bd11565b'
  }],
  SessionId: ''
}, {
  CreationTime: '2021-05-20T17:45:59',
  Id: '48c00930-b25d-4ccc-ccb3-08d91bb720f6',
  Operation: 'ModifyFolderPermissions',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 2,
  ResultStatus: 'Succeeded',
  UserKey: 'S-1-5-18',
  UserType: 2,
  Version: 1,
  Workload: 'Exchange',
  ClientIP: '::1',
  UserId: 'S-1-5-18',
  ClientIPAddress: '::1',
  ClientInfoString: 'Client=WebServices;Action=ConfigureGroupMailbox',
  ExternalAccess: true,
  InternalLogonType: 1,
  LogonType: 1,
  LogonUserSid: 'S-1-5-18',
  MailboxGuid: 'fc108b45-9d51-4b87-a473-9d5a0e404966',
  MailboxOwnerMasterAccountSid: 'S-1-5-10',
  MailboxOwnerSid: 'S-1-5-21-2986565805-1835265550-1383574073-20743067',
  MailboxOwnerUPN: 'TestSharePoint@wazuh.com',
  OrganizationName: 'wazuh.testytest.com',
  OriginatingServer: 'AS8PR04MB8465 (15.20.4150.023)\r\n',
  Item: {
    Id: 'LgAAAAA6tVhba3JWSaGmky7/7OvfAQDRwKc47c1sT4Waab6O4zbPAAAAAAENAAAC',
    ParentFolder: {
      Id: 'LgAAAAA6tVhba3JWSaGmky7/7OvfAQDRwKc47c1sT4Waab6O4zbPAAAAAAENAAAC',
      MemberRights: 'ReadAny, Create, EditOwned, DeleteOwned, EditAny, DeleteAny, Visible, FreeBusySimple, FreeBusyDetailed',
      MemberSid: 'S-1-8-4228942661-1267178833-1520268196-1716076558-1',
      MemberUpn: 'Member@local',
      Name: 'Calendar',
      Path: '\\Calendar'
    }
  }
}, {
  CreationTime: '2021-05-20T17:45:58',
  Id: 'bb03b48e-609d-477b-cb80-08d91bb72077',
  Operation: 'Create',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 2,
  ResultStatus: 'Succeeded',
  UserKey: 'S-1-5-18',
  UserType: 2,
  Version: 1,
  Workload: 'Exchange',
  ClientIP: '::1',
  UserId: 'S-1-5-18',
  ClientIPAddress: '::1',
  ClientInfoString: 'Client=WebServices;Action=ConfigureGroupMailbox',
  ExternalAccess: true,
  InternalLogonType: 1,
  LogonType: 1,
  LogonUserSid: 'S-1-5-18',
  MailboxGuid: 'fc108b45-9d51-4b87-a473-9d5a0e404966',
  MailboxOwnerMasterAccountSid: 'S-1-5-10',
  MailboxOwnerSid: 'S-1-5-21-2986565805-1835265550-1383574073-20743067',
  MailboxOwnerUPN: 'TestSharePoint@wazuh.com',
  OrganizationName: 'wazuh.testytest.com',
  OriginatingServer: 'AS8PR04MB8465 (15.20.4150.023)\r\n',
  Item: {
    Attachments: 'warming_email_03_2017_calendar.png (646b); warming_email_03_2017_conversation.png (661b); warming_email_03_2017_links.png (1450b); google_play_store_badge.png (4871b); apple_store_badge.png (4493b); windows_store_badge.png (3728b); warming_email_03_2017_files.png (856b); warming_email_03_2017_sharePoint.png (1479b)',
    Id: 'RgAAAAA6tVhba3JWSaGmky7/7OvfBwDRwKc47c1sT4Waab6O4zbPAAAAAAEMAADRwKc47c1sT4Waab6O4zbPAAAAAAk9AAAJ',
    InternetMessageId: '<AS8PR04MB846542106D3939F2D1952D05D32A9@AS8PR04MB8465.eurprd04.prod.outlook.com>',
    IsRecord: false,
    ParentFolder: {
      Id: 'LgAAAAA6tVhba3JWSaGmky7/7OvfAQDRwKc47c1sT4Waab6O4zbPAAAAAAEMAAAB',
      Path: '\\Inbox'
    },
    Subject: 'The new TestSharePoint group is ready'
  }
}, {
  CreationTime: '2021-05-20T17:59:59',
  Id: 'e855fb12-2d48-45f3-ac8d-08d91bb91569',
  Operation: 'Remove-UnifiedGroup',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 1,
  ResultStatus: 'True',
  UserKey: 'NT AUTHORITY\\SYSTEM (w3wp)',
  UserType: 2,
  Version: 1,
  Workload: 'Exchange',
  ClientIP: '[2a01:111:f402:ac00::f134]:51514',
  ObjectId: 'TestSharePoint_b47e06bf-895d-48c4-8ae4-a0fdc60ec249',
  UserId: 'NT AUTHORITY\\SYSTEM (w3wp)',
  AppId: '00000003-0000-0ff1-ce00-000000000000',
  ClientAppId: '00000003-0000-0ff1-ce00-000000000000',
  ExternalAccess: false,
  OrganizationName: 'wazuh.testytest.com',
  OriginatingServer: 'VI1PR04MB6125 (15.20.4129.033)',
  Parameters: [{
    Name: 'Identity',
    Value: 'b47e06bf-895d-48c4-8ae4-a0fdc60ec249'
  }],
  SessionId: ''
}, {
  CreationTime: '2021-05-20T18:04:37',
  Id: 'f111c82c-7961-473d-112a-08d91bb9bb91',
  Operation: 'Set-UnifiedGroup',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 1,
  ResultStatus: 'True',
  UserKey: 'SpoolsProvisioning-ApplicationAccount@eurprd04.prod.outlook.com',
  UserType: 3,
  Version: 1,
  Workload: 'Exchange',
  ClientIP: '51.144.33.14:58849',
  ObjectId: 'EURPR04A010.prod.outlook.com/Microsoft Exchange Hosted Organizations/wazuh.testytest.com/Soft Deleted Objects/TestSharePoint_b47e06bf-895d-48c4-8ae4-a0fdc60ec249',
  UserId: 'SpoolsProvisioning-ApplicationAccount@eurprd04.prod.outlook.com',
  AppId: '61109738-7d2b-4a0b-9fe3-660b1ff83505',
  ClientAppId: '',
  ExternalAccess: true,
  OrganizationName: 'wazuh.testytest.com',
  OriginatingServer: 'VI1PR0402MB3326 (15.20.4129.033)',
  Parameters: [{
    Name: 'Identity',
    Value: 'MGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViXDFlYjFjNjZhLTRhYWQtNGY2Mi04NjAzLTdjMDRkZTIxYWE3Mg2'
  }, {
    Name: 'EmailAddresses',
    Value: 'smtp:TestSharePoint@wazuh.testytest.com;SMTP:TestSharePoint@wazuh.com'
  }, {
    Name: 'IncludeSoftDeletedObjects',
    Value: 'True'
  }],
  SessionId: ''
}, {
  CreationTime: '2021-05-20T18:59:49',
  Id: '32229114-e357-4b56-9d08-08d91bc1717c',
  Operation: 'Set-User',
  OrganizationId: '0fea4e03-8146-453b-b889-54b4bd11565b',
  RecordType: 1,
  ResultStatus: 'True',
  UserKey: 'NT AUTHORITY\\SYSTEM (Microsoft.Exchange.Management.ForwardSync)',
  UserType: 3,
  Version: 1,
  Workload: 'Exchange',
  ObjectId: 'EURPR04A010.prod.outlook.com/Microsoft Exchange Hosted Organizations/wazuh.testytest.com/tomas.turina',
  UserId: 'NT AUTHORITY\\SYSTEM (Microsoft.Exchange.Management.ForwardSync)',
  AppId: '',
  ClientAppId: '',
  ExternalAccess: true,
  OrganizationName: 'wazuh.testytest.com',
  OriginatingServer: 'DB8PR04MB7065 (15.20.4150.023)',
  Parameters: [{
    Name: 'Identity',
    Value: '0fea4e03-8146-453b-b889-54b4bd11565b\\bdbb8236-0f48-4fc6-9f77-914cdcc02b3c'
  }, {
    Name: 'SyncMailboxLocationGuids',
    Value: 'True'
  }, {
    Name: 'ErrorAction',
    Value: 'Stop'
  }, {
    Name: 'WarningAction',
    Value: 'SilentlyContinue'
  }]
}];
exports.arrayLogs = arrayLogs;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm9mZmljZS5qcyJdLCJuYW1lcyI6WyJhcnJheU9mZmljZUdyb3VwcyIsImFycmF5TG9jYXRpb25PZmZpY2UiLCJhcnJheURlY29kZXJPZmZpY2UiLCJuYW1lIiwiYXJyYXlVdWlkT2ZmaWNlIiwiYXJyYXlEZXZpY2VQcm9wZXJ0aWVzT2ZmaWNlIiwiTmFtZSIsIlZhbHVlIiwiYXJyYXlJcCIsImFycmF5VXNlcklkIiwiYXJyYXlUYXJnZXRPZmZpY2UiLCJJRCIsIlR5cGUiLCJhcnJheUFjdG9yT2ZmaWNlIiwiYXJyYXlFeHRlbmRlZFByb3BlcnRpZXNPZmZpY2UiLCJvZmZpY2VSdWxlcyIsImRhdGEiLCJvZmZpY2UzNjUiLCJSZWNvcmRUeXBlIiwiU3Vic2NyaXB0aW9uIiwicnVsZSIsImxldmVsIiwiZGVzY3JpcHRpb24iLCJpZCIsIm1haWwiLCJmaXJlZHRpbWVzIiwiZ3JvdXBzIiwiYXJyYXlMb2dzIiwiSWQiLCJPcGVyYXRpb24iLCJPcmdhbml6YXRpb25JZCIsIlVzZXJLZXkiLCJVc2VyVHlwZSIsIlZlcnNpb24iLCJXb3JrbG9hZCIsIlVzZXJJZCIsIkFhZEFwcElkIiwiRGF0YVR5cGUiLCJEYXRhYmFzZVR5cGUiLCJSZWxhdGl2ZVVybCIsIlJlc3VsdENvdW50IiwiQ3JlYXRpb25UaW1lIiwiUmVzdWx0U3RhdHVzIiwiT2JqZWN0SWQiLCJTZWN1cml0eUNvbXBsaWFuY2VDZW50ZXJFdmVudFR5cGUiLCJDbGllbnRBcHBsaWNhdGlvbiIsIkNtZGxldFZlcnNpb24iLCJFZmZlY3RpdmVPcmdhbml6YXRpb24iLCJOb25QSUlQYXJhbWV0ZXJzIiwiUGFyYW1ldGVycyIsIlN0YXJ0VGltZSIsIlVzZXJTZXJ2aWNlUGxhbiIsIkNsaWVudElQIiwiQXp1cmVBY3RpdmVEaXJlY3RvcnlFdmVudFR5cGUiLCJFeHRlbmRlZFByb3BlcnRpZXMiLCJNb2RpZmllZFByb3BlcnRpZXMiLCJBY3RvciIsIkFjdG9yQ29udGV4dElkIiwiQWN0b3JJcEFkZHJlc3MiLCJJbnRlclN5c3RlbXNJZCIsIkludHJhU3lzdGVtSWQiLCJTdXBwb3J0VGlja2V0SWQiLCJUYXJnZXQiLCJUYXJnZXRDb250ZXh0SWQiLCJBcHBsaWNhdGlvbklkIiwiRGV2aWNlUHJvcGVydGllcyIsIkVycm9yTnVtYmVyIiwiTmV3VmFsdWUiLCJPbGRWYWx1ZSIsIkNvcnJlbGF0aW9uSWQiLCJFdmVudFNvdXJjZSIsIkl0ZW1UeXBlIiwiU2l0ZSIsIlVzZXJBZ2VudCIsIkV2ZW50RGF0YSIsIldlYklkIiwiVGFyZ2V0VXNlck9yR3JvdXBUeXBlIiwiU2l0ZVVybCIsIlRhcmdldFVzZXJPckdyb3VwTmFtZSIsIkN1c3RvbVVuaXF1ZUlkIiwiTGlzdEl0ZW1VbmlxdWVJZCIsIkxpc3RJZCIsIlNvdXJjZUZpbGVFeHRlbnNpb24iLCJTb3VyY2VGaWxlTmFtZSIsIlNvdXJjZVJlbGF0aXZlVXJsIiwiRG9Ob3REaXN0cmlidXRlRXZlbnQiLCJDdXN0b21pemVkRG9jbGliIiwiRnJvbUFwcCIsIklzRG9jTGliIiwiSXRlbUNvdW50IiwiTGlzdEJhc2VUZW1wbGF0ZVR5cGUiLCJMaXN0QmFzZVR5cGUiLCJMaXN0Q29sb3IiLCJMaXN0SWNvbiIsIlNvdXJjZSIsIlRlbXBsYXRlVHlwZUlkIiwiTGlzdFRpdGxlIiwiSGlnaFByaW9yaXR5TWVkaWFQcm9jZXNzaW5nIiwiRGVzdGluYXRpb25GaWxlRXh0ZW5zaW9uIiwiRGVzdGluYXRpb25GaWxlTmFtZSIsIkRlc3RpbmF0aW9uUmVsYXRpdmVVcmwiLCJBcHBJZCIsIkNsaWVudEFwcElkIiwiRXh0ZXJuYWxBY2Nlc3MiLCJPcmdhbml6YXRpb25OYW1lIiwiT3JpZ2luYXRpbmdTZXJ2ZXIiLCJTZXNzaW9uSWQiLCJDbGllbnRJUEFkZHJlc3MiLCJDbGllbnRJbmZvU3RyaW5nIiwiSW50ZXJuYWxMb2dvblR5cGUiLCJMb2dvblR5cGUiLCJMb2dvblVzZXJTaWQiLCJNYWlsYm94R3VpZCIsIk1haWxib3hPd25lck1hc3RlckFjY291bnRTaWQiLCJNYWlsYm94T3duZXJTaWQiLCJNYWlsYm94T3duZXJVUE4iLCJJdGVtIiwiUGFyZW50Rm9sZGVyIiwiTWVtYmVyUmlnaHRzIiwiTWVtYmVyU2lkIiwiTWVtYmVyVXBuIiwiUGF0aCIsIkF0dGFjaG1lbnRzIiwiSW50ZXJuZXRNZXNzYWdlSWQiLCJJc1JlY29yZCIsIlN1YmplY3QiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRU8sTUFBTUEsaUJBQWlCLEdBQUcsQ0FBQyxXQUFELEVBQWMsOEJBQWQsQ0FBMUI7O0FBRUEsTUFBTUMsbUJBQW1CLEdBQUcsV0FBNUI7O0FBRUEsTUFBTUMsa0JBQWtCLEdBQUcsQ0FDaEM7QUFDRUMsRUFBQUEsSUFBSSxFQUFFO0FBRFIsQ0FEZ0MsQ0FBM0I7O0FBTUEsTUFBTUMsZUFBZSxHQUFHLENBQzdCLHNDQUQ2QixFQUU3QixzQ0FGNkIsRUFHN0Isc0NBSDZCLEVBSTdCLHNDQUo2QixFQUs3QixzQ0FMNkIsRUFNN0Isc0NBTjZCLEVBTzdCLHNDQVA2QixFQVE3QixzQ0FSNkIsRUFTN0Isc0NBVDZCLEVBVTdCLHNDQVY2QixFQVc3QixzQ0FYNkIsRUFZN0Isc0NBWjZCLEVBYTdCLHNDQWI2QixFQWM3QixzQ0FkNkIsRUFlN0Isc0NBZjZCLEVBZ0I3QixzQ0FoQjZCLEVBaUI3QixzQ0FqQjZCLEVBa0I3QixzQ0FsQjZCLEVBbUI3QixzQ0FuQjZCLEVBb0I3QixzQ0FwQjZCLENBQXhCOztBQXVCQSxNQUFNQywyQkFBMkIsR0FBRyxDQUN6QztBQUNFQyxFQUFBQSxJQUFJLEVBQUUsYUFEUjtBQUVFQyxFQUFBQSxLQUFLLEVBQUU7QUFGVCxDQUR5QyxFQUt6QztBQUNFRCxFQUFBQSxJQUFJLEVBQUUsdUJBRFI7QUFFRUMsRUFBQUEsS0FBSyxFQUFFO0FBRlQsQ0FMeUMsRUFTekM7QUFDRUQsRUFBQUEsSUFBSSxFQUFFLFdBRFI7QUFFRUMsRUFBQUEsS0FBSyxFQUFFO0FBRlQsQ0FUeUMsQ0FBcEM7O0FBZUEsTUFBTUMsT0FBTyxHQUFHLENBQ3JCLGVBRHFCLEVBRXJCLGdCQUZxQixFQUdyQixnQkFIcUIsRUFJckIsY0FKcUIsRUFLckIsYUFMcUIsRUFNckIsZUFOcUIsRUFPckIsY0FQcUIsRUFRckIsY0FScUIsQ0FBaEI7O0FBVUEsTUFBTUMsV0FBVyxHQUFHLENBQ3pCLGlCQUR5QixFQUV6QixvQkFGeUIsRUFHekIsaUJBSHlCLEVBSXpCLGlCQUp5QixFQUt6QixpQkFMeUIsQ0FBcEI7O0FBT0EsTUFBTUMsaUJBQWlCLEdBQUcsQ0FDL0I7QUFDRUMsRUFBQUEsRUFBRSxFQUFFLHNDQUROO0FBRUVDLEVBQUFBLElBQUksRUFBRTtBQUZSLENBRCtCLENBQTFCOztBQU9BLE1BQU1DLGdCQUFnQixHQUFHLENBQzlCO0FBQ0VGLEVBQUFBLEVBQUUsRUFBRSxzQ0FETjtBQUVFQyxFQUFBQSxJQUFJLEVBQUU7QUFGUixDQUQ4QixFQUs5QjtBQUNFRCxFQUFBQSxFQUFFLEVBQUUsZ0JBRE47QUFFRUMsRUFBQUEsSUFBSSxFQUFFO0FBRlIsQ0FMOEIsQ0FBekI7O0FBV0EsTUFBTUUsNkJBQTZCLEdBQUcsQ0FDM0M7QUFDRVIsRUFBQUEsSUFBSSxFQUFFLG9CQURSO0FBRUVDLEVBQUFBLEtBQUssRUFBRTtBQUZULENBRDJDLEVBSzNDO0FBQ0VELEVBQUFBLElBQUksRUFBRSxXQURSO0FBRUVDLEVBQUFBLEtBQUssRUFDSDtBQUhKLENBTDJDLEVBVTNDO0FBQ0VELEVBQUFBLElBQUksRUFBRSxhQURSO0FBRUVDLEVBQUFBLEtBQUssRUFBRTtBQUZULENBVjJDLENBQXRDOztBQWdCQSxNQUFNUSxXQUFXLEdBQUc7QUFDekIsS0FBRztBQUNEQyxJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsU0FBUyxFQUFFO0FBQ1RDLFFBQUFBLFVBQVUsRUFBRSxDQURIO0FBRVRDLFFBQUFBLFlBQVksRUFBRTtBQUZMO0FBRFAsS0FETDtBQU9EQyxJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsS0FBSyxFQUFFLENBREg7QUFFSkMsTUFBQUEsV0FBVyxFQUFFLHVEQUZUO0FBR0pDLE1BQUFBLEVBQUUsRUFBRSxPQUhBO0FBSUpDLE1BQUFBLElBQUksRUFBRSxLQUpGO0FBS0pDLE1BQUFBLFVBQVUsRUFBRSxDQUxSO0FBTUpDLE1BQUFBLE1BQU0sRUFBRSxDQUFDLFdBQUQsRUFBYyxlQUFkLEVBQStCLGlCQUEvQixFQUFrRCxnQkFBbEQsRUFBb0UsZ0JBQXBFO0FBTko7QUFQTCxHQURzQjtBQWlCekIsS0FBRztBQUNEVixJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsU0FBUyxFQUFFO0FBQ1RDLFFBQUFBLFVBQVUsRUFBRSxDQURIO0FBRVRDLFFBQUFBLFlBQVksRUFBRTtBQUZMO0FBRFAsS0FETDtBQU9EQyxJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsS0FBSyxFQUFFLENBREg7QUFFSkMsTUFBQUEsV0FBVyxFQUNULHdKQUhFO0FBSUpDLE1BQUFBLEVBQUUsRUFBRSxPQUpBO0FBS0pDLE1BQUFBLElBQUksRUFBRSxLQUxGO0FBTUpDLE1BQUFBLFVBQVUsRUFBRSxDQU5SO0FBT0pDLE1BQUFBLE1BQU0sRUFBRSxDQUFDLFdBQUQsRUFBYyxjQUFkLEVBQThCLGlCQUE5QixFQUFpRCxnQkFBakQ7QUFQSjtBQVBMLEdBakJzQjtBQWtDekIsS0FBRztBQUNEVixJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsU0FBUyxFQUFFO0FBQ1RDLFFBQUFBLFVBQVUsRUFBRSxDQURIO0FBRVRDLFFBQUFBLFlBQVksRUFBRTtBQUZMO0FBRFAsS0FETDtBQU9EQyxJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsS0FBSyxFQUFFLENBREg7QUFFSkMsTUFBQUEsV0FBVyxFQUFFLGdDQUZUO0FBR0pDLE1BQUFBLEVBQUUsRUFBRSxPQUhBO0FBSUpDLE1BQUFBLElBQUksRUFBRSxLQUpGO0FBS0pDLE1BQUFBLFVBQVUsRUFBRSxDQUxSO0FBTUpDLE1BQUFBLE1BQU0sRUFBRSxDQUFDLFdBQUQsRUFBYyxZQUFkLEVBQTRCLGlCQUE1QixFQUErQyxnQkFBL0M7QUFOSjtBQVBMLEdBbENzQjtBQWtEekIsS0FBRztBQUNEVixJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsU0FBUyxFQUFFO0FBQ1RDLFFBQUFBLFVBQVUsRUFBRSxDQURIO0FBRVRDLFFBQUFBLFlBQVksRUFBRTtBQUZMO0FBRFAsS0FETDtBQU9EQyxJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsS0FBSyxFQUFFLENBREg7QUFFSkMsTUFBQUEsV0FBVyxFQUFFLCtDQUZUO0FBR0pDLE1BQUFBLEVBQUUsRUFBRSxPQUhBO0FBSUpDLE1BQUFBLElBQUksRUFBRSxLQUpGO0FBS0pDLE1BQUFBLFVBQVUsRUFBRSxDQUxSO0FBTUpDLE1BQUFBLE1BQU0sRUFBRSxDQUNOLFdBRE0sRUFFTix5QkFGTSxFQUdOLGlCQUhNLEVBSU4sbUJBSk0sRUFLTixnQkFMTSxFQU1OLGNBTk07QUFOSjtBQVBMLEdBbERzQjtBQXlFekIsS0FBRztBQUNEVixJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsU0FBUyxFQUFFO0FBQ1RDLFFBQUFBLFVBQVUsRUFBRSxDQURIO0FBRVRDLFFBQUFBLFlBQVksRUFBRTtBQUZMO0FBRFAsS0FETDtBQU9EQyxJQUFBQSxJQUFJLEVBQUU7QUFDSkMsTUFBQUEsS0FBSyxFQUFFLENBREg7QUFFSkMsTUFBQUEsV0FBVyxFQUFFLDRDQUZUO0FBR0pDLE1BQUFBLEVBQUUsRUFBRSxPQUhBO0FBSUpDLE1BQUFBLElBQUksRUFBRSxLQUpGO0FBS0pDLE1BQUFBLFVBQVUsRUFBRSxDQUxSO0FBTUpDLE1BQUFBLE1BQU0sRUFBRSxDQUFDLFdBQUQsRUFBYyxzQkFBZCxFQUFzQyxpQkFBdEMsRUFBeUQsZ0JBQXpEO0FBTko7QUFQTCxHQXpFc0I7QUF5RnpCLE1BQUk7QUFDRlYsSUFBQUEsSUFBSSxFQUFFO0FBQ0pDLE1BQUFBLFNBQVMsRUFBRTtBQUNUQyxRQUFBQSxVQUFVLEVBQUUsRUFESDtBQUVUQyxRQUFBQSxZQUFZLEVBQUU7QUFGTDtBQURQLEtBREo7QUFPRkMsSUFBQUEsSUFBSSxFQUFFO0FBQ0pDLE1BQUFBLEtBQUssRUFBRSxDQURIO0FBRUpDLE1BQUFBLFdBQVcsRUFBRSx3Q0FGVDtBQUdKQyxNQUFBQSxFQUFFLEVBQUUsT0FIQTtBQUlKQyxNQUFBQSxJQUFJLEVBQUUsS0FKRjtBQUtKQyxNQUFBQSxVQUFVLEVBQUUsQ0FMUjtBQU1KQyxNQUFBQSxNQUFNLEVBQUUsQ0FBQyxXQUFELEVBQWMsWUFBZCxFQUE0QixpQkFBNUIsRUFBK0MsZ0JBQS9DO0FBTko7QUFQSixHQXpGcUI7QUF5R3pCLE1BQUk7QUFDRlYsSUFBQUEsSUFBSSxFQUFFO0FBQ0pDLE1BQUFBLFNBQVMsRUFBRTtBQUNUQyxRQUFBQSxVQUFVLEVBQUUsRUFESDtBQUVUQyxRQUFBQSxZQUFZLEVBQUU7QUFGTDtBQURQLEtBREo7QUFPRkMsSUFBQUEsSUFBSSxFQUFFO0FBQ0pDLE1BQUFBLEtBQUssRUFBRSxDQURIO0FBRUpDLE1BQUFBLFdBQVcsRUFBRSxnRkFGVDtBQUdKQyxNQUFBQSxFQUFFLEVBQUUsT0FIQTtBQUlKQyxNQUFBQSxJQUFJLEVBQUUsS0FKRjtBQUtKQyxNQUFBQSxVQUFVLEVBQUUsQ0FMUjtBQU1KQyxNQUFBQSxNQUFNLEVBQUUsQ0FDTixXQURNLEVBRU4sOEJBRk0sRUFHTixxQ0FITSxFQUlOLGlCQUpNLEVBS04sc0JBTE0sRUFNTiw0QkFOTTtBQU5KO0FBUEosR0F6R3FCO0FBZ0l6QixNQUFJO0FBQ0ZWLElBQUFBLElBQUksRUFBRTtBQUNKQyxNQUFBQSxTQUFTLEVBQUU7QUFDVEMsUUFBQUEsVUFBVSxFQUFFLEVBREg7QUFFVEMsUUFBQUEsWUFBWSxFQUFFO0FBRkw7QUFEUCxLQURKO0FBT0ZDLElBQUFBLElBQUksRUFBRTtBQUNKQyxNQUFBQSxLQUFLLEVBQUUsQ0FESDtBQUVKQyxNQUFBQSxXQUFXLEVBQUUsb0VBRlQ7QUFHSkMsTUFBQUEsRUFBRSxFQUFFLE9BSEE7QUFJSkMsTUFBQUEsSUFBSSxFQUFFLEtBSkY7QUFLSkMsTUFBQUEsVUFBVSxFQUFFLENBTFI7QUFNSkMsTUFBQUEsTUFBTSxFQUFFLENBQ04sV0FETSxFQUVOLG1DQUZNLEVBR04saUJBSE0sRUFJTixnQkFKTSxFQUtOLGdCQUxNO0FBTko7QUFQSixHQWhJcUI7QUFzSnpCLE1BQUk7QUFDRlYsSUFBQUEsSUFBSSxFQUFFO0FBQ0pDLE1BQUFBLFNBQVMsRUFBRTtBQUNUQyxRQUFBQSxVQUFVLEVBQUUsRUFESDtBQUVUQyxRQUFBQSxZQUFZLEVBQUU7QUFGTDtBQURQLEtBREo7QUFPRkMsSUFBQUEsSUFBSSxFQUFFO0FBQ0pDLE1BQUFBLEtBQUssRUFBRSxDQURIO0FBRUpDLE1BQUFBLFdBQVcsRUFBRSxxQ0FGVDtBQUdKQyxNQUFBQSxFQUFFLEVBQUUsT0FIQTtBQUlKQyxNQUFBQSxJQUFJLEVBQUUsS0FKRjtBQUtKQyxNQUFBQSxVQUFVLEVBQUUsQ0FMUjtBQU1KQyxNQUFBQSxNQUFNLEVBQUUsQ0FBQyxXQUFELEVBQWMseUJBQWQsRUFBeUMsaUJBQXpDLEVBQTRELGdCQUE1RDtBQU5KO0FBUEosR0F0SnFCO0FBc0t6QixNQUFJO0FBQ0ZWLElBQUFBLElBQUksRUFBRTtBQUNKQyxNQUFBQSxTQUFTLEVBQUU7QUFDVEMsUUFBQUEsVUFBVSxFQUFFLEVBREg7QUFFVEMsUUFBQUEsWUFBWSxFQUFFO0FBRkw7QUFEUCxLQURKO0FBT0ZDLElBQUFBLElBQUksRUFBRTtBQUNKQyxNQUFBQSxLQUFLLEVBQUUsQ0FESDtBQUVKQyxNQUFBQSxXQUFXLEVBQUUsNENBRlQ7QUFHSkMsTUFBQUEsRUFBRSxFQUFFLE9BSEE7QUFJSkMsTUFBQUEsSUFBSSxFQUFFLEtBSkY7QUFLSkMsTUFBQUEsVUFBVSxFQUFFLENBTFI7QUFNSkMsTUFBQUEsTUFBTSxFQUFFLENBQUMsV0FBRCxFQUFjLDBCQUFkLEVBQTBDLGlCQUExQyxFQUE2RCxnQkFBN0Q7QUFOSjtBQVBKO0FBdEtxQixDQUFwQjs7QUF1TEEsTUFBTUMsU0FBUyxHQUFHLENBQ3ZCO0FBQ0VDLEVBQUFBLEVBQUUsRUFBRSxzQ0FETjtBQUVFQyxFQUFBQSxTQUFTLEVBQUUsZ0NBRmI7QUFHRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUhsQjtBQUlFWixFQUFBQSxVQUFVLEVBQUUsRUFKZDtBQUtFYSxFQUFBQSxPQUFPLEVBQUUsZ0JBTFg7QUFNRUMsRUFBQUEsUUFBUSxFQUFFLENBTlo7QUFPRUMsRUFBQUEsT0FBTyxFQUFFLENBUFg7QUFRRUMsRUFBQUEsUUFBUSxFQUFFLDBCQVJaO0FBU0VDLEVBQUFBLE1BQU0sRUFBRSxnQkFUVjtBQVVFQyxFQUFBQSxRQUFRLEVBQUUsc0NBVlo7QUFXRUMsRUFBQUEsUUFBUSxFQUFFLDBCQVhaO0FBWUVDLEVBQUFBLFlBQVksRUFBRSxXQVpoQjtBQWFFQyxFQUFBQSxXQUFXLEVBQ1QsbUhBZEo7QUFlRUMsRUFBQUEsV0FBVyxFQUFFO0FBZmYsQ0FEdUIsRUFrQnZCO0FBQ0VaLEVBQUFBLEVBQUUsRUFBRSxzQ0FETjtBQUVFQyxFQUFBQSxTQUFTLEVBQUUsYUFGYjtBQUdFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSGxCO0FBSUVaLEVBQUFBLFVBQVUsRUFBRSxFQUpkO0FBS0VhLEVBQUFBLE9BQU8sRUFBRSxzQ0FMWDtBQU1FQyxFQUFBQSxRQUFRLEVBQUUsQ0FOWjtBQU9FQyxFQUFBQSxPQUFPLEVBQUUsQ0FQWDtBQVFFQyxFQUFBQSxRQUFRLEVBQUUsMEJBUlo7QUFTRUMsRUFBQUEsTUFBTSxFQUFFLHNDQVRWO0FBVUVDLEVBQUFBLFFBQVEsRUFBRSxzQ0FWWjtBQVdFQyxFQUFBQSxRQUFRLEVBQUUsT0FYWjtBQVlFQyxFQUFBQSxZQUFZLEVBQUUsY0FaaEI7QUFhRUMsRUFBQUEsV0FBVyxFQUNULHNUQWRKO0FBZUVDLEVBQUFBLFdBQVcsRUFBRTtBQWZmLENBbEJ1QixFQW1DdkI7QUFDRUMsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLHNCQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLEVBTGQ7QUFNRWEsRUFBQUEsT0FBTyxFQUFFLHNDQU5YO0FBT0VDLEVBQUFBLFFBQVEsRUFBRSxDQVBaO0FBUUVDLEVBQUFBLE9BQU8sRUFBRSxDQVJYO0FBU0VDLEVBQUFBLFFBQVEsRUFBRSwwQkFUWjtBQVVFQyxFQUFBQSxNQUFNLEVBQUUsc0NBVlY7QUFXRUMsRUFBQUEsUUFBUSxFQUFFLHNDQVhaO0FBWUVDLEVBQUFBLFFBQVEsRUFBRSxnQkFaWjtBQWFFQyxFQUFBQSxZQUFZLEVBQUUsY0FiaEI7QUFjRUMsRUFBQUEsV0FBVyxFQUNULCtUQWZKO0FBZ0JFQyxFQUFBQSxXQUFXLEVBQUU7QUFoQmYsQ0FuQ3VCLEVBcUR2QjtBQUNFQyxFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUseUJBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsRUFMZDtBQU1FYSxFQUFBQSxPQUFPLEVBQUUsZ0JBTlg7QUFPRUMsRUFBQUEsUUFBUSxFQUFFLENBUFo7QUFRRUMsRUFBQUEsT0FBTyxFQUFFLENBUlg7QUFTRUMsRUFBQUEsUUFBUSxFQUFFLDBCQVRaO0FBVUVDLEVBQUFBLE1BQU0sRUFBRSxnQkFWVjtBQVdFQyxFQUFBQSxRQUFRLEVBQUUsc0NBWFo7QUFZRUMsRUFBQUEsUUFBUSxFQUFFLGlCQVpaO0FBYUVFLEVBQUFBLFdBQVcsRUFDVCw4R0FkSjtBQWVFQyxFQUFBQSxXQUFXLEVBQUU7QUFmZixDQXJEdUIsRUFzRXZCO0FBQ0VDLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSwrQkFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxFQUxkO0FBTUV3QixFQUFBQSxZQUFZLEVBQUUsU0FOaEI7QUFPRVgsRUFBQUEsT0FBTyxFQUFFLGdCQVBYO0FBUUVDLEVBQUFBLFFBQVEsRUFBRSxDQVJaO0FBU0VDLEVBQUFBLE9BQU8sRUFBRSxDQVRYO0FBVUVDLEVBQUFBLFFBQVEsRUFBRSwwQkFWWjtBQVdFUyxFQUFBQSxRQUFRLEVBQUUsRUFYWjtBQVlFUixFQUFBQSxNQUFNLEVBQUUsZ0JBWlY7QUFhRVMsRUFBQUEsaUNBQWlDLEVBQUUsQ0FickM7QUFjRUMsRUFBQUEsaUJBQWlCLEVBQUUsS0FkckI7QUFlRUMsRUFBQUEsYUFBYSxFQUFFLEtBZmpCO0FBZ0JFQyxFQUFBQSxxQkFBcUIsRUFBRSxxQkFoQnpCO0FBaUJFQyxFQUFBQSxnQkFBZ0IsRUFBRSxFQWpCcEI7QUFrQkVDLEVBQUFBLFVBQVUsRUFBRSxFQWxCZDtBQW1CRUMsRUFBQUEsU0FBUyxFQUFFLHFCQW5CYjtBQW9CRUMsRUFBQUEsZUFBZSxFQUFFO0FBcEJuQixDQXRFdUIsRUE0RnZCO0FBQ0VWLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSwrQkFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxFQUxkO0FBTUV3QixFQUFBQSxZQUFZLEVBQUUsU0FOaEI7QUFPRVgsRUFBQUEsT0FBTyxFQUFFLGdCQVBYO0FBUUVDLEVBQUFBLFFBQVEsRUFBRSxDQVJaO0FBU0VDLEVBQUFBLE9BQU8sRUFBRSxDQVRYO0FBVUVDLEVBQUFBLFFBQVEsRUFBRSwwQkFWWjtBQVdFUyxFQUFBQSxRQUFRLEVBQUUsRUFYWjtBQVlFUixFQUFBQSxNQUFNLEVBQUUsZ0JBWlY7QUFhRVMsRUFBQUEsaUNBQWlDLEVBQUUsQ0FickM7QUFjRUMsRUFBQUEsaUJBQWlCLEVBQUUsS0FkckI7QUFlRUMsRUFBQUEsYUFBYSxFQUFFLEtBZmpCO0FBZ0JFQyxFQUFBQSxxQkFBcUIsRUFBRSxxQkFoQnpCO0FBaUJFQyxFQUFBQSxnQkFBZ0IsRUFBRSxFQWpCcEI7QUFrQkVDLEVBQUFBLFVBQVUsRUFBRSxFQWxCZDtBQW1CRUMsRUFBQUEsU0FBUyxFQUFFLHFCQW5CYjtBQW9CRUMsRUFBQUEsZUFBZSxFQUFFO0FBcEJuQixDQTVGdUIsRUFrSHZCO0FBQ0VWLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSw2QkFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxFQUxkO0FBTUV3QixFQUFBQSxZQUFZLEVBQUUsU0FOaEI7QUFPRVgsRUFBQUEsT0FBTyxFQUFFLGdCQVBYO0FBUUVDLEVBQUFBLFFBQVEsRUFBRSxDQVJaO0FBU0VDLEVBQUFBLE9BQU8sRUFBRSxDQVRYO0FBVUVDLEVBQUFBLFFBQVEsRUFBRSwwQkFWWjtBQVdFUyxFQUFBQSxRQUFRLEVBQUUsRUFYWjtBQVlFUixFQUFBQSxNQUFNLEVBQUUsZ0JBWlY7QUFhRVMsRUFBQUEsaUNBQWlDLEVBQUUsQ0FickM7QUFjRUMsRUFBQUEsaUJBQWlCLEVBQUUsS0FkckI7QUFlRUMsRUFBQUEsYUFBYSxFQUFFLEtBZmpCO0FBZ0JFQyxFQUFBQSxxQkFBcUIsRUFBRSxxQkFoQnpCO0FBaUJFQyxFQUFBQSxnQkFBZ0IsRUFDZCx5RkFsQko7QUFtQkVDLEVBQUFBLFVBQVUsRUFDUiwrRkFwQko7QUFxQkVDLEVBQUFBLFNBQVMsRUFBRSxxQkFyQmI7QUFzQkVDLEVBQUFBLGVBQWUsRUFBRTtBQXRCbkIsQ0FsSHVCLEVBMEl2QjtBQUNFVixFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUsNENBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsRUFMZDtBQU1Fd0IsRUFBQUEsWUFBWSxFQUFFLFNBTmhCO0FBT0VYLEVBQUFBLE9BQU8sRUFBRSxnQkFQWDtBQVFFQyxFQUFBQSxRQUFRLEVBQUUsQ0FSWjtBQVNFQyxFQUFBQSxPQUFPLEVBQUUsQ0FUWDtBQVVFQyxFQUFBQSxRQUFRLEVBQUUsMEJBVlo7QUFXRVMsRUFBQUEsUUFBUSxFQUFFLEVBWFo7QUFZRVIsRUFBQUEsTUFBTSxFQUFFLGdCQVpWO0FBYUVTLEVBQUFBLGlDQUFpQyxFQUFFLENBYnJDO0FBY0VDLEVBQUFBLGlCQUFpQixFQUFFLEtBZHJCO0FBZUVDLEVBQUFBLGFBQWEsRUFBRSxLQWZqQjtBQWdCRUMsRUFBQUEscUJBQXFCLEVBQUUscUJBaEJ6QjtBQWlCRUMsRUFBQUEsZ0JBQWdCLEVBQUUsRUFqQnBCO0FBa0JFQyxFQUFBQSxVQUFVLEVBQUUsRUFsQmQ7QUFtQkVDLEVBQUFBLFNBQVMsRUFBRSxxQkFuQmI7QUFvQkVDLEVBQUFBLGVBQWUsRUFBRTtBQXBCbkIsQ0ExSXVCLEVBZ0t2QjtBQUNFVixFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUscUNBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsRUFMZDtBQU1Fd0IsRUFBQUEsWUFBWSxFQUFFLFNBTmhCO0FBT0VYLEVBQUFBLE9BQU8sRUFBRSxnQkFQWDtBQVFFQyxFQUFBQSxRQUFRLEVBQUUsQ0FSWjtBQVNFQyxFQUFBQSxPQUFPLEVBQUUsQ0FUWDtBQVVFQyxFQUFBQSxRQUFRLEVBQUUsMEJBVlo7QUFXRVMsRUFBQUEsUUFBUSxFQUFFLEVBWFo7QUFZRVIsRUFBQUEsTUFBTSxFQUFFLGdCQVpWO0FBYUVTLEVBQUFBLGlDQUFpQyxFQUFFLENBYnJDO0FBY0VDLEVBQUFBLGlCQUFpQixFQUFFLEtBZHJCO0FBZUVDLEVBQUFBLGFBQWEsRUFBRSxLQWZqQjtBQWdCRUMsRUFBQUEscUJBQXFCLEVBQUUscUJBaEJ6QjtBQWlCRUMsRUFBQUEsZ0JBQWdCLEVBQUUsRUFqQnBCO0FBa0JFQyxFQUFBQSxVQUFVLEVBQUUsRUFsQmQ7QUFtQkVDLEVBQUFBLFNBQVMsRUFBRSxxQkFuQmI7QUFvQkVDLEVBQUFBLGVBQWUsRUFBRTtBQXBCbkIsQ0FoS3VCLEVBc0x2QjtBQUNFVixFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUsNEJBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsRUFMZDtBQU1Fd0IsRUFBQUEsWUFBWSxFQUFFLFNBTmhCO0FBT0VYLEVBQUFBLE9BQU8sRUFBRSxnQkFQWDtBQVFFQyxFQUFBQSxRQUFRLEVBQUUsQ0FSWjtBQVNFQyxFQUFBQSxPQUFPLEVBQUUsQ0FUWDtBQVVFQyxFQUFBQSxRQUFRLEVBQUUsMEJBVlo7QUFXRVMsRUFBQUEsUUFBUSxFQUFFLEVBWFo7QUFZRVIsRUFBQUEsTUFBTSxFQUFFLGdCQVpWO0FBYUVTLEVBQUFBLGlDQUFpQyxFQUFFLENBYnJDO0FBY0VDLEVBQUFBLGlCQUFpQixFQUFFLEtBZHJCO0FBZUVDLEVBQUFBLGFBQWEsRUFBRSxLQWZqQjtBQWdCRUMsRUFBQUEscUJBQXFCLEVBQUUscUJBaEJ6QjtBQWlCRUMsRUFBQUEsZ0JBQWdCLEVBQUUsc0JBakJwQjtBQWtCRUMsRUFBQUEsVUFBVSxFQUFFLGdCQWxCZDtBQW1CRUMsRUFBQUEsU0FBUyxFQUFFLHFCQW5CYjtBQW9CRUMsRUFBQUEsZUFBZSxFQUFFO0FBcEJuQixDQXRMdUIsRUE0TXZCO0FBQ0VWLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSxtQkFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxFQUxkO0FBTUV3QixFQUFBQSxZQUFZLEVBQUUsU0FOaEI7QUFPRVgsRUFBQUEsT0FBTyxFQUFFLGdCQVBYO0FBUUVDLEVBQUFBLFFBQVEsRUFBRSxDQVJaO0FBU0VDLEVBQUFBLE9BQU8sRUFBRSxDQVRYO0FBVUVDLEVBQUFBLFFBQVEsRUFBRSwwQkFWWjtBQVdFUyxFQUFBQSxRQUFRLEVBQUUsRUFYWjtBQVlFUixFQUFBQSxNQUFNLEVBQUUsZ0JBWlY7QUFhRVMsRUFBQUEsaUNBQWlDLEVBQUUsQ0FickM7QUFjRUMsRUFBQUEsaUJBQWlCLEVBQUUsS0FkckI7QUFlRUMsRUFBQUEsYUFBYSxFQUFFLEtBZmpCO0FBZ0JFQyxFQUFBQSxxQkFBcUIsRUFBRSxxQkFoQnpCO0FBaUJFQyxFQUFBQSxnQkFBZ0IsRUFBRSxtQ0FqQnBCO0FBa0JFQyxFQUFBQSxVQUFVLEVBQUUsNkJBbEJkO0FBbUJFQyxFQUFBQSxTQUFTLEVBQUUscUJBbkJiO0FBb0JFQyxFQUFBQSxlQUFlLEVBQUU7QUFwQm5CLENBNU11QixFQWtPdkI7QUFDRVYsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLHNCQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLEVBTGQ7QUFNRXdCLEVBQUFBLFlBQVksRUFBRSxTQU5oQjtBQU9FWCxFQUFBQSxPQUFPLEVBQUUsZ0JBUFg7QUFRRUMsRUFBQUEsUUFBUSxFQUFFLENBUlo7QUFTRUMsRUFBQUEsT0FBTyxFQUFFLENBVFg7QUFVRUMsRUFBQUEsUUFBUSxFQUFFLDBCQVZaO0FBV0VTLEVBQUFBLFFBQVEsRUFBRSxFQVhaO0FBWUVSLEVBQUFBLE1BQU0sRUFBRSxnQkFaVjtBQWFFUyxFQUFBQSxpQ0FBaUMsRUFBRSxDQWJyQztBQWNFQyxFQUFBQSxpQkFBaUIsRUFBRSxLQWRyQjtBQWVFQyxFQUFBQSxhQUFhLEVBQUUsS0FmakI7QUFnQkVDLEVBQUFBLHFCQUFxQixFQUFFLHFCQWhCekI7QUFpQkVDLEVBQUFBLGdCQUFnQixFQUFFLHlCQWpCcEI7QUFrQkVDLEVBQUFBLFVBQVUsRUFBRSx5QkFsQmQ7QUFtQkVDLEVBQUFBLFNBQVMsRUFBRSxxQkFuQmI7QUFvQkVDLEVBQUFBLGVBQWUsRUFBRTtBQXBCbkIsQ0FsT3VCLEVBd1B2QjtBQUNFVixFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUsaUNBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsRUFMZDtBQU1Fd0IsRUFBQUEsWUFBWSxFQUFFLFNBTmhCO0FBT0VYLEVBQUFBLE9BQU8sRUFBRSxnQkFQWDtBQVFFQyxFQUFBQSxRQUFRLEVBQUUsQ0FSWjtBQVNFQyxFQUFBQSxPQUFPLEVBQUUsQ0FUWDtBQVVFQyxFQUFBQSxRQUFRLEVBQUUsMEJBVlo7QUFXRVMsRUFBQUEsUUFBUSxFQUFFLEVBWFo7QUFZRVIsRUFBQUEsTUFBTSxFQUFFLGdCQVpWO0FBYUVTLEVBQUFBLGlDQUFpQyxFQUFFLENBYnJDO0FBY0VDLEVBQUFBLGlCQUFpQixFQUFFLEVBZHJCO0FBZUVDLEVBQUFBLGFBQWEsRUFBRSxLQWZqQjtBQWdCRUMsRUFBQUEscUJBQXFCLEVBQUUscUJBaEJ6QjtBQWlCRUMsRUFBQUEsZ0JBQWdCLEVBQUUsc0RBakJwQjtBQWtCRUMsRUFBQUEsVUFBVSxFQUFFLHNEQWxCZDtBQW1CRUMsRUFBQUEsU0FBUyxFQUFFLHFCQW5CYjtBQW9CRUMsRUFBQUEsZUFBZSxFQUFFO0FBcEJuQixDQXhQdUIsRUE4UXZCO0FBQ0VWLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSxjQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLEVBTGQ7QUFNRXdCLEVBQUFBLFlBQVksRUFBRSxTQU5oQjtBQU9FWCxFQUFBQSxPQUFPLEVBQUUsc0NBUFg7QUFRRUMsRUFBQUEsUUFBUSxFQUFFLENBUlo7QUFTRUMsRUFBQUEsT0FBTyxFQUFFLENBVFg7QUFVRUMsRUFBQUEsUUFBUSxFQUFFLHNCQVZaO0FBV0VrQixFQUFBQSxRQUFRLEVBQUUsY0FYWjtBQVlFVCxFQUFBQSxRQUFRLEVBQUUsc0NBWlo7QUFhRVIsRUFBQUEsTUFBTSxFQUFFLGdCQWJWO0FBY0VrQixFQUFBQSw2QkFBNkIsRUFBRSxDQWRqQztBQWVFQyxFQUFBQSxrQkFBa0IsRUFBRSxDQUNsQjtBQUNFaEQsSUFBQUEsSUFBSSxFQUFFLG9CQURSO0FBRUVDLElBQUFBLEtBQUssRUFBRTtBQUZULEdBRGtCLEVBS2xCO0FBQ0VELElBQUFBLElBQUksRUFBRSxXQURSO0FBRUVDLElBQUFBLEtBQUssRUFDSDtBQUhKLEdBTGtCLEVBVWxCO0FBQ0VELElBQUFBLElBQUksRUFBRSxhQURSO0FBRUVDLElBQUFBLEtBQUssRUFBRTtBQUZULEdBVmtCLENBZnRCO0FBOEJFZ0QsRUFBQUEsa0JBQWtCLEVBQUUsRUE5QnRCO0FBK0JFQyxFQUFBQSxLQUFLLEVBQUUsQ0FDTDtBQUNFN0MsSUFBQUEsRUFBRSxFQUFFLHNDQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBREssRUFLTDtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsZ0JBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FMSyxDQS9CVDtBQXlDRTZDLEVBQUFBLGNBQWMsRUFBRSxzQ0F6Q2xCO0FBMENFQyxFQUFBQSxjQUFjLEVBQUUsY0ExQ2xCO0FBMkNFQyxFQUFBQSxjQUFjLEVBQUUsc0NBM0NsQjtBQTRDRUMsRUFBQUEsYUFBYSxFQUFFLHNDQTVDakI7QUE2Q0VDLEVBQUFBLGVBQWUsRUFBRSxFQTdDbkI7QUE4Q0VDLEVBQUFBLE1BQU0sRUFBRSxDQUNOO0FBQ0VuRCxJQUFBQSxFQUFFLEVBQUUsc0NBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FETSxDQTlDVjtBQW9ERW1ELEVBQUFBLGVBQWUsRUFBRSxzQ0FwRG5CO0FBcURFQyxFQUFBQSxhQUFhLEVBQUUsc0NBckRqQjtBQXNERUMsRUFBQUEsZ0JBQWdCLEVBQUUsQ0FDaEI7QUFDRTNELElBQUFBLElBQUksRUFBRSxJQURSO0FBRUVDLElBQUFBLEtBQUssRUFBRTtBQUZULEdBRGdCLEVBS2hCO0FBQ0VELElBQUFBLElBQUksRUFBRSxhQURSO0FBRUVDLElBQUFBLEtBQUssRUFBRTtBQUZULEdBTGdCLEVBU2hCO0FBQ0VELElBQUFBLElBQUksRUFBRSx1QkFEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQUU7QUFGVCxHQVRnQixFQWFoQjtBQUNFRCxJQUFBQSxJQUFJLEVBQUUsV0FEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQUU7QUFGVCxHQWJnQixDQXREcEI7QUF3RUUyRCxFQUFBQSxXQUFXLEVBQUU7QUF4RWYsQ0E5UXVCLEVBd1Z2QjtBQUNFekIsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLHdCQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLENBTGQ7QUFNRXdCLEVBQUFBLFlBQVksRUFBRSxTQU5oQjtBQU9FWCxFQUFBQSxPQUFPLEVBQUUsZUFQWDtBQVFFQyxFQUFBQSxRQUFRLEVBQUUsQ0FSWjtBQVNFQyxFQUFBQSxPQUFPLEVBQUUsQ0FUWDtBQVVFQyxFQUFBQSxRQUFRLEVBQUUsc0JBVlo7QUFXRVMsRUFBQUEsUUFBUSxFQUFFLHNDQVhaO0FBWUVSLEVBQUFBLE1BQU0sRUFBRSx1REFaVjtBQWFFa0IsRUFBQUEsNkJBQTZCLEVBQUUsQ0FiakM7QUFjRUMsRUFBQUEsa0JBQWtCLEVBQUUsQ0FDbEI7QUFDRWhELElBQUFBLElBQUksRUFBRSxtQkFEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQUU7QUFGVCxHQURrQixFQUtsQjtBQUNFRCxJQUFBQSxJQUFJLEVBQUUsNEJBRFI7QUFFRUMsSUFBQUEsS0FBSyxFQUFFO0FBRlQsR0FMa0IsQ0FkdEI7QUF3QkVnRCxFQUFBQSxrQkFBa0IsRUFBRSxDQUNsQjtBQUNFakQsSUFBQUEsSUFBSSxFQUFFLGdCQURSO0FBRUU2RCxJQUFBQSxRQUFRLEVBQUUsa0JBRlo7QUFHRUMsSUFBQUEsUUFBUSxFQUFFO0FBSFosR0FEa0IsRUFNbEI7QUFDRTlELElBQUFBLElBQUksRUFBRSxnQkFEUjtBQUVFNkQsSUFBQUEsUUFBUSxFQUFFLG9EQUZaO0FBR0VDLElBQUFBLFFBQVEsRUFBRTtBQUhaLEdBTmtCLEVBV2xCO0FBQ0U5RCxJQUFBQSxJQUFJLEVBQUUsYUFEUjtBQUVFNkQsSUFBQUEsUUFBUSxFQUFFLCtCQUZaO0FBR0VDLElBQUFBLFFBQVEsRUFBRTtBQUhaLEdBWGtCLEVBZ0JsQjtBQUNFOUQsSUFBQUEsSUFBSSxFQUFFLHNCQURSO0FBRUU2RCxJQUFBQSxRQUFRLEVBQUUsb0RBRlo7QUFHRUMsSUFBQUEsUUFBUSxFQUFFO0FBSFosR0FoQmtCLEVBcUJsQjtBQUNFOUQsSUFBQUEsSUFBSSxFQUFFLFlBRFI7QUFFRTZELElBQUFBLFFBQVEsRUFDTiwyS0FISjtBQUlFQyxJQUFBQSxRQUFRLEVBQUU7QUFKWixHQXJCa0IsRUEyQmxCO0FBQ0U5RCxJQUFBQSxJQUFJLEVBQUUsNkJBRFI7QUFFRTZELElBQUFBLFFBQVEsRUFBRSwrRUFGWjtBQUdFQyxJQUFBQSxRQUFRLEVBQUU7QUFIWixHQTNCa0IsRUFnQ2xCO0FBQ0U5RCxJQUFBQSxJQUFJLEVBQUUsZ0NBRFI7QUFFRTZELElBQUFBLFFBQVEsRUFBRSxzQ0FGWjtBQUdFQyxJQUFBQSxRQUFRLEVBQUU7QUFIWixHQWhDa0IsQ0F4QnRCO0FBOERFWixFQUFBQSxLQUFLLEVBQUUsQ0FDTDtBQUNFN0MsSUFBQUEsRUFBRSxFQUFFLHNDQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBREssRUFLTDtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsc0NBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FMSyxFQVNMO0FBQ0VELElBQUFBLEVBQUUsRUFBRSx1REFETjtBQUVFQyxJQUFBQSxJQUFJLEVBQUU7QUFGUixHQVRLLEVBYUw7QUFDRUQsSUFBQUEsRUFBRSxFQUFFLHNDQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBYkssRUFpQkw7QUFDRUQsSUFBQUEsRUFBRSxFQUFFLGtCQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBakJLLENBOURUO0FBb0ZFNkMsRUFBQUEsY0FBYyxFQUFFLHNDQXBGbEI7QUFxRkVFLEVBQUFBLGNBQWMsRUFBRSxzQ0FyRmxCO0FBc0ZFQyxFQUFBQSxhQUFhLEVBQUUsc0NBdEZqQjtBQXVGRUMsRUFBQUEsZUFBZSxFQUFFLEVBdkZuQjtBQXdGRUMsRUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRW5ELElBQUFBLEVBQUUsRUFBRSx1REFETjtBQUVFQyxJQUFBQSxJQUFJLEVBQUU7QUFGUixHQURNLEVBS047QUFDRUQsSUFBQUEsRUFBRSxFQUFFLHNDQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBTE0sRUFTTjtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsa0JBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FUTSxFQWFOO0FBQ0VELElBQUFBLEVBQUUsRUFBRSxpQkFETjtBQUVFQyxJQUFBQSxJQUFJLEVBQUU7QUFGUixHQWJNLEVBaUJOO0FBQ0VELElBQUFBLEVBQUUsRUFBRSxzQ0FETjtBQUVFQyxJQUFBQSxJQUFJLEVBQUU7QUFGUixHQWpCTSxFQXFCTjtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsc0NBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FyQk0sQ0F4RlY7QUFrSEVtRCxFQUFBQSxlQUFlLEVBQUU7QUFsSG5CLENBeFZ1QixFQTRjdkI7QUFDRXRCLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSxzQkFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxDQUxkO0FBTUV3QixFQUFBQSxZQUFZLEVBQUUsU0FOaEI7QUFPRVgsRUFBQUEsT0FBTyxFQUFFLDRCQVBYO0FBUUVDLEVBQUFBLFFBQVEsRUFBRSxDQVJaO0FBU0VDLEVBQUFBLE9BQU8sRUFBRSxDQVRYO0FBVUVDLEVBQUFBLFFBQVEsRUFBRSxzQkFWWjtBQVdFUyxFQUFBQSxRQUFRLEVBQUUsZ0JBWFo7QUFZRVIsRUFBQUEsTUFBTSxFQUFFLGdCQVpWO0FBYUVrQixFQUFBQSw2QkFBNkIsRUFBRSxDQWJqQztBQWNFQyxFQUFBQSxrQkFBa0IsRUFBRSxDQUNsQjtBQUNFaEQsSUFBQUEsSUFBSSxFQUFFLG1CQURSO0FBRUVDLElBQUFBLEtBQUssRUFBRTtBQUZULEdBRGtCLEVBS2xCO0FBQ0VELElBQUFBLElBQUksRUFBRSw0QkFEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQUU7QUFGVCxHQUxrQixDQWR0QjtBQXdCRWdELEVBQUFBLGtCQUFrQixFQUFFLEVBeEJ0QjtBQXlCRUMsRUFBQUEsS0FBSyxFQUFFLENBQ0w7QUFDRTdDLElBQUFBLEVBQUUsRUFBRSxnQkFETjtBQUVFQyxJQUFBQSxJQUFJLEVBQUU7QUFGUixHQURLLEVBS0w7QUFDRUQsSUFBQUEsRUFBRSxFQUFFLGtCQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBTEssRUFTTDtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsMkNBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FUSyxFQWFMO0FBQ0VELElBQUFBLEVBQUUsRUFBRSxzQ0FETjtBQUVFQyxJQUFBQSxJQUFJLEVBQUU7QUFGUixHQWJLLEVBaUJMO0FBQ0VELElBQUFBLEVBQUUsRUFBRSxNQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBakJLLENBekJUO0FBK0NFNkMsRUFBQUEsY0FBYyxFQUFFLHNDQS9DbEI7QUFnREVFLEVBQUFBLGNBQWMsRUFBRSxzQ0FoRGxCO0FBaURFQyxFQUFBQSxhQUFhLEVBQUUsc0NBakRqQjtBQWtERUMsRUFBQUEsZUFBZSxFQUFFLEVBbERuQjtBQW1ERUMsRUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRW5ELElBQUFBLEVBQUUsRUFBRSwyQ0FETjtBQUVFQyxJQUFBQSxJQUFJLEVBQUU7QUFGUixHQURNLEVBS047QUFDRUQsSUFBQUEsRUFBRSxFQUFFLHNDQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBTE0sRUFTTjtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsTUFETjtBQUVFQyxJQUFBQSxJQUFJLEVBQUU7QUFGUixHQVRNLEVBYU47QUFDRUQsSUFBQUEsRUFBRSxFQUFFLGdCQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBYk0sRUFpQk47QUFDRUQsSUFBQUEsRUFBRSxFQUFFLGtCQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBakJNLENBbkRWO0FBeUVFbUQsRUFBQUEsZUFBZSxFQUFFO0FBekVuQixDQTVjdUIsRUF1aEJ2QjtBQUNFdEIsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLGNBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsQ0FMZDtBQU1Fd0IsRUFBQUEsWUFBWSxFQUFFLFNBTmhCO0FBT0VYLEVBQUFBLE9BQU8sRUFBRSw0QkFQWDtBQVFFQyxFQUFBQSxRQUFRLEVBQUUsQ0FSWjtBQVNFQyxFQUFBQSxPQUFPLEVBQUUsQ0FUWDtBQVVFQyxFQUFBQSxRQUFRLEVBQUUsc0JBVlo7QUFXRVMsRUFBQUEsUUFBUSxFQUFFLGdCQVhaO0FBWUVSLEVBQUFBLE1BQU0sRUFBRSxnQkFaVjtBQWFFa0IsRUFBQUEsNkJBQTZCLEVBQUUsQ0FiakM7QUFjRUMsRUFBQUEsa0JBQWtCLEVBQUUsQ0FDbEI7QUFDRWhELElBQUFBLElBQUksRUFBRSxtQkFEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQUU7QUFGVCxHQURrQixFQUtsQjtBQUNFRCxJQUFBQSxJQUFJLEVBQUUsNEJBRFI7QUFFRUMsSUFBQUEsS0FBSyxFQUFFO0FBRlQsR0FMa0IsQ0FkdEI7QUF3QkVnRCxFQUFBQSxrQkFBa0IsRUFBRSxDQUNsQjtBQUNFakQsSUFBQUEsSUFBSSxFQUFFLGlCQURSO0FBRUU2RCxJQUFBQSxRQUFRLEVBQ04seUpBSEo7QUFJRUMsSUFBQUEsUUFBUSxFQUFFO0FBSlosR0FEa0IsRUFPbEI7QUFDRTlELElBQUFBLElBQUksRUFBRSxjQURSO0FBRUU2RCxJQUFBQSxRQUFRLEVBQ04seVZBSEo7QUFJRUMsSUFBQUEsUUFBUSxFQUFFO0FBSlosR0FQa0IsRUFhbEI7QUFDRTlELElBQUFBLElBQUksRUFBRSw2QkFEUjtBQUVFNkQsSUFBQUEsUUFBUSxFQUFFLCtCQUZaO0FBR0VDLElBQUFBLFFBQVEsRUFBRTtBQUhaLEdBYmtCLEVBa0JsQjtBQUNFOUQsSUFBQUEsSUFBSSxFQUFFLG1CQURSO0FBRUU2RCxJQUFBQSxRQUFRLEVBQUUsUUFGWjtBQUdFQyxJQUFBQSxRQUFRLEVBQUU7QUFIWixHQWxCa0IsQ0F4QnRCO0FBZ0RFWixFQUFBQSxLQUFLLEVBQUUsQ0FDTDtBQUNFN0MsSUFBQUEsRUFBRSxFQUFFLGdCQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBREssRUFLTDtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsa0JBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FMSyxFQVNMO0FBQ0VELElBQUFBLEVBQUUsRUFBRSwyQ0FETjtBQUVFQyxJQUFBQSxJQUFJLEVBQUU7QUFGUixHQVRLLEVBYUw7QUFDRUQsSUFBQUEsRUFBRSxFQUFFLHNDQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBYkssRUFpQkw7QUFDRUQsSUFBQUEsRUFBRSxFQUFFLE1BRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FqQkssQ0FoRFQ7QUFzRUU2QyxFQUFBQSxjQUFjLEVBQUUsc0NBdEVsQjtBQXVFRUUsRUFBQUEsY0FBYyxFQUFFLHNDQXZFbEI7QUF3RUVDLEVBQUFBLGFBQWEsRUFBRSxzQ0F4RWpCO0FBeUVFQyxFQUFBQSxlQUFlLEVBQUUsRUF6RW5CO0FBMEVFQyxFQUFBQSxNQUFNLEVBQUUsQ0FDTjtBQUNFbkQsSUFBQUEsRUFBRSxFQUFFLDJDQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBRE0sRUFLTjtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsc0NBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FMTSxFQVNOO0FBQ0VELElBQUFBLEVBQUUsRUFBRSxNQUROO0FBRUVDLElBQUFBLElBQUksRUFBRTtBQUZSLEdBVE0sRUFhTjtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsZ0JBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FiTSxFQWlCTjtBQUNFRCxJQUFBQSxFQUFFLEVBQUUsa0JBRE47QUFFRUMsSUFBQUEsSUFBSSxFQUFFO0FBRlIsR0FqQk0sQ0ExRVY7QUFnR0VtRCxFQUFBQSxlQUFlLEVBQUU7QUFoR25CLENBdmhCdUIsRUF5bkJ2QjtBQUNFdEIsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLHNCQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLENBTGQ7QUFNRWEsRUFBQUEsT0FBTyxFQUFFLDZDQU5YO0FBT0VDLEVBQUFBLFFBQVEsRUFBRSxDQVBaO0FBUUVDLEVBQUFBLE9BQU8sRUFBRSxDQVJYO0FBU0VDLEVBQUFBLFFBQVEsRUFBRSxVQVRaO0FBVUVrQixFQUFBQSxRQUFRLEVBQUUsZUFWWjtBQVdFVCxFQUFBQSxRQUFRLEVBQUUsaUVBWFo7QUFZRVIsRUFBQUEsTUFBTSxFQUFFLGdCQVpWO0FBYUVrQyxFQUFBQSxhQUFhLEVBQUUsc0NBYmpCO0FBY0VDLEVBQUFBLFdBQVcsRUFBRSxZQWRmO0FBZUVDLEVBQUFBLFFBQVEsRUFBRSxNQWZaO0FBZ0JFQyxFQUFBQSxJQUFJLEVBQUUsc0NBaEJSO0FBaUJFQyxFQUFBQSxTQUFTLEVBQ1AscUhBbEJKO0FBbUJFbEIsRUFBQUEsa0JBQWtCLEVBQUUsQ0FDbEI7QUFDRWpELElBQUFBLElBQUksRUFBRSwwQkFEUjtBQUVFNkQsSUFBQUEsUUFBUSxFQUFFLFNBRlo7QUFHRUMsSUFBQUEsUUFBUSxFQUFFO0FBSFosR0FEa0I7QUFuQnRCLENBem5CdUIsRUFvcEJ2QjtBQUNFM0IsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLHVCQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLENBTGQ7QUFNRWEsRUFBQUEsT0FBTyxFQUFFLDZDQU5YO0FBT0VDLEVBQUFBLFFBQVEsRUFBRSxDQVBaO0FBUUVDLEVBQUFBLE9BQU8sRUFBRSxDQVJYO0FBU0VDLEVBQUFBLFFBQVEsRUFBRSxVQVRaO0FBVUVrQixFQUFBQSxRQUFRLEVBQUUsZUFWWjtBQVdFVCxFQUFBQSxRQUFRLEVBQUUsaUVBWFo7QUFZRVIsRUFBQUEsTUFBTSxFQUFFLGdCQVpWO0FBYUVrQyxFQUFBQSxhQUFhLEVBQUUsc0NBYmpCO0FBY0VDLEVBQUFBLFdBQVcsRUFBRSxZQWRmO0FBZUVDLEVBQUFBLFFBQVEsRUFBRSxNQWZaO0FBZ0JFQyxFQUFBQSxJQUFJLEVBQUUsc0NBaEJSO0FBaUJFQyxFQUFBQSxTQUFTLEVBQ1AscUhBbEJKO0FBbUJFQyxFQUFBQSxTQUFTLEVBQ1A7QUFwQkosQ0FwcEJ1QixFQTBxQnZCO0FBQ0VqQyxFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUsNEJBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsRUFMZDtBQU1FYSxFQUFBQSxPQUFPLEVBQUUsNkNBTlg7QUFPRUMsRUFBQUEsUUFBUSxFQUFFLENBUFo7QUFRRUMsRUFBQUEsT0FBTyxFQUFFLENBUlg7QUFTRUMsRUFBQUEsUUFBUSxFQUFFLFVBVFo7QUFVRWtCLEVBQUFBLFFBQVEsRUFBRSxlQVZaO0FBV0VULEVBQUFBLFFBQVEsRUFBRSxpRUFYWjtBQVlFUixFQUFBQSxNQUFNLEVBQUUsZ0JBWlY7QUFhRWtDLEVBQUFBLGFBQWEsRUFBRSxzQ0FiakI7QUFjRUMsRUFBQUEsV0FBVyxFQUFFLFlBZGY7QUFlRUMsRUFBQUEsUUFBUSxFQUFFLEtBZlo7QUFnQkVDLEVBQUFBLElBQUksRUFBRSxzQ0FoQlI7QUFpQkVDLEVBQUFBLFNBQVMsRUFDUCxxSEFsQko7QUFtQkVFLEVBQUFBLEtBQUssRUFBRSxzQ0FuQlQ7QUFvQkVwQixFQUFBQSxrQkFBa0IsRUFBRSxDQUNsQjtBQUNFakQsSUFBQUEsSUFBSSxFQUFFLFdBRFI7QUFFRTZELElBQUFBLFFBQVEsRUFBRSxFQUZaO0FBR0VDLElBQUFBLFFBQVEsRUFBRTtBQUhaLEdBRGtCLENBcEJ0QjtBQTJCRVEsRUFBQUEscUJBQXFCLEVBQUUsUUEzQnpCO0FBNEJFQyxFQUFBQSxPQUFPLEVBQUUsaUVBNUJYO0FBNkJFQyxFQUFBQSxxQkFBcUIsRUFBRTtBQTdCekIsQ0ExcUJ1QixFQXlzQnZCO0FBQ0VyQyxFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUsMEJBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsRUFMZDtBQU1FYSxFQUFBQSxPQUFPLEVBQUUsNkNBTlg7QUFPRUMsRUFBQUEsUUFBUSxFQUFFLENBUFo7QUFRRUMsRUFBQUEsT0FBTyxFQUFFLENBUlg7QUFTRUMsRUFBQUEsUUFBUSxFQUFFLFVBVFo7QUFVRWtCLEVBQUFBLFFBQVEsRUFBRSxlQVZaO0FBV0VULEVBQUFBLFFBQVEsRUFBRSxpRUFYWjtBQVlFUixFQUFBQSxNQUFNLEVBQUUsZ0JBWlY7QUFhRWtDLEVBQUFBLGFBQWEsRUFBRSxzQ0FiakI7QUFjRUMsRUFBQUEsV0FBVyxFQUFFLFlBZGY7QUFlRUMsRUFBQUEsUUFBUSxFQUFFLEtBZlo7QUFnQkVDLEVBQUFBLElBQUksRUFBRSxzQ0FoQlI7QUFpQkVDLEVBQUFBLFNBQVMsRUFDUCxxSEFsQko7QUFtQkVFLEVBQUFBLEtBQUssRUFBRSxzQ0FuQlQ7QUFvQkVwQixFQUFBQSxrQkFBa0IsRUFBRSxDQUNsQjtBQUNFakQsSUFBQUEsSUFBSSxFQUFFLFdBRFI7QUFFRTZELElBQUFBLFFBQVEsRUFBRSxnQkFGWjtBQUdFQyxJQUFBQSxRQUFRLEVBQUU7QUFIWixHQURrQixDQXBCdEI7QUEyQkVRLEVBQUFBLHFCQUFxQixFQUFFLFFBM0J6QjtBQTRCRUMsRUFBQUEsT0FBTyxFQUFFLGlFQTVCWDtBQTZCRUMsRUFBQUEscUJBQXFCLEVBQUU7QUE3QnpCLENBenNCdUIsRUF3dUJ2QjtBQUNFckMsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLFlBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsQ0FMZDtBQU1FYSxFQUFBQSxPQUFPLEVBQUUsNkNBTlg7QUFPRUMsRUFBQUEsUUFBUSxFQUFFLENBUFo7QUFRRUMsRUFBQUEsT0FBTyxFQUFFLENBUlg7QUFTRUMsRUFBQUEsUUFBUSxFQUFFLFlBVFo7QUFVRWtCLEVBQUFBLFFBQVEsRUFBRSxjQVZaO0FBV0VULEVBQUFBLFFBQVEsRUFBRSwyREFYWjtBQVlFUixFQUFBQSxNQUFNLEVBQUUsZ0JBWlY7QUFhRWtDLEVBQUFBLGFBQWEsRUFBRSxzQ0FiakI7QUFjRVUsRUFBQUEsY0FBYyxFQUFFLElBZGxCO0FBZUVULEVBQUFBLFdBQVcsRUFBRSxZQWZmO0FBZ0JFQyxFQUFBQSxRQUFRLEVBQUUsTUFoQlo7QUFpQkVTLEVBQUFBLGdCQUFnQixFQUFFLHNDQWpCcEI7QUFrQkVSLEVBQUFBLElBQUksRUFBRSxzQ0FsQlI7QUFtQkVDLEVBQUFBLFNBQVMsRUFDUCxxSEFwQko7QUFxQkVFLEVBQUFBLEtBQUssRUFBRTtBQXJCVCxDQXh1QnVCLEVBK3ZCdkI7QUFDRWxDLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSxjQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLEVBTGQ7QUFNRWEsRUFBQUEsT0FBTyxFQUFFLDZDQU5YO0FBT0VDLEVBQUFBLFFBQVEsRUFBRSxDQVBaO0FBUUVDLEVBQUFBLE9BQU8sRUFBRSxDQVJYO0FBU0VDLEVBQUFBLFFBQVEsRUFBRSxZQVRaO0FBVUVrQixFQUFBQSxRQUFRLEVBQUUsY0FWWjtBQVdFVCxFQUFBQSxRQUFRLEVBQUUsbURBWFo7QUFZRVIsRUFBQUEsTUFBTSxFQUFFLGdCQVpWO0FBYUVrQyxFQUFBQSxhQUFhLEVBQUUsc0NBYmpCO0FBY0VDLEVBQUFBLFdBQVcsRUFBRSxZQWRmO0FBZUVDLEVBQUFBLFFBQVEsRUFBRSxLQWZaO0FBZ0JFQyxFQUFBQSxJQUFJLEVBQUUsc0NBaEJSO0FBaUJFQyxFQUFBQSxTQUFTLEVBQ1AscUhBbEJKO0FBbUJFRSxFQUFBQSxLQUFLLEVBQUUsc0NBbkJUO0FBb0JFRCxFQUFBQSxTQUFTLEVBQUUsNEJBcEJiO0FBcUJFRSxFQUFBQSxxQkFBcUIsRUFBRSxRQXJCekI7QUFzQkVDLEVBQUFBLE9BQU8sRUFBRSxtREF0Qlg7QUF1QkVDLEVBQUFBLHFCQUFxQixFQUFFO0FBdkJ6QixDQS92QnVCLEVBd3hCdkI7QUFDRXJDLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSxjQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLENBTGQ7QUFNRWEsRUFBQUEsT0FBTyxFQUFFLDZDQU5YO0FBT0VDLEVBQUFBLFFBQVEsRUFBRSxDQVBaO0FBUUVDLEVBQUFBLE9BQU8sRUFBRSxDQVJYO0FBU0VDLEVBQUFBLFFBQVEsRUFBRSxZQVRaO0FBVUVrQixFQUFBQSxRQUFRLEVBQUUsY0FWWjtBQVdFVCxFQUFBQSxRQUFRLEVBQ04sd0ZBWko7QUFhRVIsRUFBQUEsTUFBTSxFQUFFLGdCQWJWO0FBY0VrQyxFQUFBQSxhQUFhLEVBQUUsc0NBZGpCO0FBZUVDLEVBQUFBLFdBQVcsRUFBRSxZQWZmO0FBZ0JFQyxFQUFBQSxRQUFRLEVBQUUsTUFoQlo7QUFpQkVVLEVBQUFBLE1BQU0sRUFBRSxzQ0FqQlY7QUFrQkVELEVBQUFBLGdCQUFnQixFQUFFLHNDQWxCcEI7QUFtQkVSLEVBQUFBLElBQUksRUFBRSxzQ0FuQlI7QUFvQkVDLEVBQUFBLFNBQVMsRUFDUCxxSEFyQko7QUFzQkVFLEVBQUFBLEtBQUssRUFBRSxzQ0F0QlQ7QUF1QkVPLEVBQUFBLG1CQUFtQixFQUFFLE1BdkJ2QjtBQXdCRUwsRUFBQUEsT0FBTyxFQUFFLG9EQXhCWDtBQXlCRU0sRUFBQUEsY0FBYyxFQUFFLGVBekJsQjtBQTBCRUMsRUFBQUEsaUJBQWlCLEVBQUU7QUExQnJCLENBeHhCdUIsRUFvekJ2QjtBQUNFM0MsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLFlBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsRUFMZDtBQU1FYSxFQUFBQSxPQUFPLEVBQUUsNkNBTlg7QUFPRUMsRUFBQUEsUUFBUSxFQUFFLENBUFo7QUFRRUMsRUFBQUEsT0FBTyxFQUFFLENBUlg7QUFTRUMsRUFBQUEsUUFBUSxFQUFFLFlBVFo7QUFVRWtCLEVBQUFBLFFBQVEsRUFBRSxjQVZaO0FBV0VULEVBQUFBLFFBQVEsRUFDTix3RkFaSjtBQWFFUixFQUFBQSxNQUFNLEVBQUUsZ0JBYlY7QUFjRWtDLEVBQUFBLGFBQWEsRUFBRSxzQ0FkakI7QUFlRWdCLEVBQUFBLG9CQUFvQixFQUFFLElBZnhCO0FBZ0JFZixFQUFBQSxXQUFXLEVBQUUsWUFoQmY7QUFpQkVDLEVBQUFBLFFBQVEsRUFBRSxNQWpCWjtBQWtCRVUsRUFBQUEsTUFBTSxFQUFFLHNDQWxCVjtBQW1CRVQsRUFBQUEsSUFBSSxFQUFFLHNDQW5CUjtBQW9CRUMsRUFBQUEsU0FBUyxFQUNQLHFIQXJCSjtBQXNCRUUsRUFBQUEsS0FBSyxFQUFFLHNDQXRCVDtBQXVCRVcsRUFBQUEsZ0JBQWdCLEVBQUUsS0F2QnBCO0FBd0JFQyxFQUFBQSxPQUFPLEVBQUUsSUF4Qlg7QUF5QkVDLEVBQUFBLFFBQVEsRUFBRSxJQXpCWjtBQTBCRUMsRUFBQUEsU0FBUyxFQUFFLENBMUJiO0FBMkJFQyxFQUFBQSxvQkFBb0IsRUFBRSxLQTNCeEI7QUE0QkVDLEVBQUFBLFlBQVksRUFBRSxpQkE1QmhCO0FBNkJFQyxFQUFBQSxTQUFTLEVBQUUsRUE3QmI7QUE4QkVDLEVBQUFBLFFBQVEsRUFBRSxFQTlCWjtBQStCRUMsRUFBQUEsTUFBTSxFQUFFLFNBL0JWO0FBZ0NFQyxFQUFBQSxjQUFjLEVBQUUsRUFoQ2xCO0FBaUNFQyxFQUFBQSxTQUFTLEVBQUU7QUFqQ2IsQ0FwekJ1QixFQXUxQnZCO0FBQ0V2RCxFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUsZ0JBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsQ0FMZDtBQU1FYSxFQUFBQSxPQUFPLEVBQUUsNkNBTlg7QUFPRUMsRUFBQUEsUUFBUSxFQUFFLENBUFo7QUFRRUMsRUFBQUEsT0FBTyxFQUFFLENBUlg7QUFTRUMsRUFBQUEsUUFBUSxFQUFFLFlBVFo7QUFVRWtCLEVBQUFBLFFBQVEsRUFBRSxjQVZaO0FBV0VULEVBQUFBLFFBQVEsRUFBRSxtREFYWjtBQVlFUixFQUFBQSxNQUFNLEVBQUUsZ0JBWlY7QUFhRWtDLEVBQUFBLGFBQWEsRUFBRSxzQ0FiakI7QUFjRVUsRUFBQUEsY0FBYyxFQUFFLEtBZGxCO0FBZUVULEVBQUFBLFdBQVcsRUFBRSxZQWZmO0FBZ0JFQyxFQUFBQSxRQUFRLEVBQUUsTUFoQlo7QUFpQkVVLEVBQUFBLE1BQU0sRUFBRSxzQ0FqQlY7QUFrQkVELEVBQUFBLGdCQUFnQixFQUFFLHNDQWxCcEI7QUFtQkVSLEVBQUFBLElBQUksRUFBRSxzQ0FuQlI7QUFvQkVDLEVBQUFBLFNBQVMsRUFDUCxxSEFyQko7QUFzQkVFLEVBQUFBLEtBQUssRUFBRTtBQXRCVCxDQXYxQnVCLEVBKzJCdkI7QUFDRWxDLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSxnQkFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxDQUxkO0FBTUVhLEVBQUFBLE9BQU8sRUFBRSw2Q0FOWDtBQU9FQyxFQUFBQSxRQUFRLEVBQUUsQ0FQWjtBQVFFQyxFQUFBQSxPQUFPLEVBQUUsQ0FSWDtBQVNFQyxFQUFBQSxRQUFRLEVBQUUsWUFUWjtBQVVFa0IsRUFBQUEsUUFBUSxFQUFFLGNBVlo7QUFXRVQsRUFBQUEsUUFBUSxFQUFFLHVFQVhaO0FBWUVSLEVBQUFBLE1BQU0sRUFBRSxnQkFaVjtBQWFFa0MsRUFBQUEsYUFBYSxFQUFFLHNDQWJqQjtBQWNFQyxFQUFBQSxXQUFXLEVBQUUsWUFkZjtBQWVFQyxFQUFBQSxRQUFRLEVBQUUsTUFmWjtBQWdCRVUsRUFBQUEsTUFBTSxFQUFFLHNDQWhCVjtBQWlCRUQsRUFBQUEsZ0JBQWdCLEVBQUUsc0NBakJwQjtBQWtCRVIsRUFBQUEsSUFBSSxFQUFFLHNDQWxCUjtBQW1CRUMsRUFBQUEsU0FBUyxFQUNQLHFIQXBCSjtBQXFCRUUsRUFBQUEsS0FBSyxFQUFFLHNDQXJCVDtBQXNCRXNCLEVBQUFBLDJCQUEyQixFQUFFLEtBdEIvQjtBQXVCRWYsRUFBQUEsbUJBQW1CLEVBQUUsTUF2QnZCO0FBd0JFTCxFQUFBQSxPQUFPLEVBQUUsb0RBeEJYO0FBeUJFTSxFQUFBQSxjQUFjLEVBQUUsV0F6QmxCO0FBMEJFQyxFQUFBQSxpQkFBaUIsRUFBRTtBQTFCckIsQ0EvMkJ1QixFQTI0QnZCO0FBQ0UzQyxFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUsYUFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxFQUxkO0FBTUVhLEVBQUFBLE9BQU8sRUFBRSw2Q0FOWDtBQU9FQyxFQUFBQSxRQUFRLEVBQUUsQ0FQWjtBQVFFQyxFQUFBQSxPQUFPLEVBQUUsQ0FSWDtBQVNFQyxFQUFBQSxRQUFRLEVBQUUsWUFUWjtBQVVFa0IsRUFBQUEsUUFBUSxFQUFFLGNBVlo7QUFXRVQsRUFBQUEsUUFBUSxFQUNOLHdGQVpKO0FBYUVSLEVBQUFBLE1BQU0sRUFBRSxnQkFiVjtBQWNFa0MsRUFBQUEsYUFBYSxFQUFFLHNDQWRqQjtBQWVFZ0IsRUFBQUEsb0JBQW9CLEVBQUUsSUFmeEI7QUFnQkVmLEVBQUFBLFdBQVcsRUFBRSxZQWhCZjtBQWlCRUMsRUFBQUEsUUFBUSxFQUFFLE1BakJaO0FBa0JFVSxFQUFBQSxNQUFNLEVBQUUsc0NBbEJWO0FBbUJFVCxFQUFBQSxJQUFJLEVBQUUsc0NBbkJSO0FBb0JFQyxFQUFBQSxTQUFTLEVBQ1AscUhBckJKO0FBc0JFRSxFQUFBQSxLQUFLLEVBQUUsc0NBdEJUO0FBdUJFVyxFQUFBQSxnQkFBZ0IsRUFBRSxLQXZCcEI7QUF3QkVDLEVBQUFBLE9BQU8sRUFBRSxLQXhCWDtBQXlCRUMsRUFBQUEsUUFBUSxFQUFFLElBekJaO0FBMEJFQyxFQUFBQSxTQUFTLEVBQUUsQ0ExQmI7QUEyQkVDLEVBQUFBLG9CQUFvQixFQUFFLEtBM0J4QjtBQTRCRUMsRUFBQUEsWUFBWSxFQUFFLGlCQTVCaEI7QUE2QkVDLEVBQUFBLFNBQVMsRUFBRSxFQTdCYjtBQThCRUMsRUFBQUEsUUFBUSxFQUFFLEVBOUJaO0FBK0JFQyxFQUFBQSxNQUFNLEVBQUUsU0EvQlY7QUFnQ0VDLEVBQUFBLGNBQWMsRUFBRSxFQWhDbEI7QUFpQ0VDLEVBQUFBLFNBQVMsRUFBRTtBQWpDYixDQTM0QnVCLEVBODZCdkI7QUFDRXZELEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSxvQkFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxDQUxkO0FBTUVhLEVBQUFBLE9BQU8sRUFBRSw2Q0FOWDtBQU9FQyxFQUFBQSxRQUFRLEVBQUUsQ0FQWjtBQVFFQyxFQUFBQSxPQUFPLEVBQUUsQ0FSWDtBQVNFQyxFQUFBQSxRQUFRLEVBQUUsWUFUWjtBQVVFa0IsRUFBQUEsUUFBUSxFQUFFLGNBVlo7QUFXRVQsRUFBQUEsUUFBUSxFQUFFLHVFQVhaO0FBWUVSLEVBQUFBLE1BQU0sRUFBRSxnQkFaVjtBQWFFa0MsRUFBQUEsYUFBYSxFQUFFLHNDQWJqQjtBQWNFVSxFQUFBQSxjQUFjLEVBQUUsS0FkbEI7QUFlRVQsRUFBQUEsV0FBVyxFQUFFLFlBZmY7QUFnQkVDLEVBQUFBLFFBQVEsRUFBRSxNQWhCWjtBQWlCRVUsRUFBQUEsTUFBTSxFQUFFLHNDQWpCVjtBQWtCRUQsRUFBQUEsZ0JBQWdCLEVBQUUsc0NBbEJwQjtBQW1CRVIsRUFBQUEsSUFBSSxFQUFFLHNDQW5CUjtBQW9CRUMsRUFBQUEsU0FBUyxFQUNQLHFIQXJCSjtBQXNCRUUsRUFBQUEsS0FBSyxFQUFFO0FBdEJULENBOTZCdUIsRUFzOEJ2QjtBQUNFbEMsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLGNBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsQ0FMZDtBQU1FYSxFQUFBQSxPQUFPLEVBQUUsNkNBTlg7QUFPRUMsRUFBQUEsUUFBUSxFQUFFLENBUFo7QUFRRUMsRUFBQUEsT0FBTyxFQUFFLENBUlg7QUFTRUMsRUFBQUEsUUFBUSxFQUFFLFlBVFo7QUFVRWtCLEVBQUFBLFFBQVEsRUFBRSxjQVZaO0FBV0VULEVBQUFBLFFBQVEsRUFBRSx1RUFYWjtBQVlFUixFQUFBQSxNQUFNLEVBQUUsZ0JBWlY7QUFhRWtDLEVBQUFBLGFBQWEsRUFBRSxzQ0FiakI7QUFjRWdCLEVBQUFBLG9CQUFvQixFQUFFLElBZHhCO0FBZUVmLEVBQUFBLFdBQVcsRUFBRSxZQWZmO0FBZ0JFQyxFQUFBQSxRQUFRLEVBQUUsTUFoQlo7QUFpQkVVLEVBQUFBLE1BQU0sRUFBRSxzQ0FqQlY7QUFrQkVELEVBQUFBLGdCQUFnQixFQUFFLHNDQWxCcEI7QUFtQkVSLEVBQUFBLElBQUksRUFBRSxzQ0FuQlI7QUFvQkVDLEVBQUFBLFNBQVMsRUFDUCxxSEFyQko7QUFzQkVFLEVBQUFBLEtBQUssRUFBRSxzQ0F0QlQ7QUF1QkVPLEVBQUFBLG1CQUFtQixFQUFFLE1BdkJ2QjtBQXdCRUwsRUFBQUEsT0FBTyxFQUFFLG9EQXhCWDtBQXlCRU0sRUFBQUEsY0FBYyxFQUFFLFdBekJsQjtBQTBCRUMsRUFBQUEsaUJBQWlCLEVBQUU7QUExQnJCLENBdDhCdUIsRUFrK0J2QjtBQUNFM0MsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLHNCQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLENBTGQ7QUFNRWEsRUFBQUEsT0FBTyxFQUFFLDZDQU5YO0FBT0VDLEVBQUFBLFFBQVEsRUFBRSxDQVBaO0FBUUVDLEVBQUFBLE9BQU8sRUFBRSxDQVJYO0FBU0VDLEVBQUFBLFFBQVEsRUFBRSxZQVRaO0FBVUVrQixFQUFBQSxRQUFRLEVBQUUsY0FWWjtBQVdFVCxFQUFBQSxRQUFRLEVBQ04sd0ZBWko7QUFhRVIsRUFBQUEsTUFBTSxFQUFFLGdCQWJWO0FBY0VrQyxFQUFBQSxhQUFhLEVBQUUsc0NBZGpCO0FBZUVDLEVBQUFBLFdBQVcsRUFBRSxZQWZmO0FBZ0JFQyxFQUFBQSxRQUFRLEVBQUUsTUFoQlo7QUFpQkVVLEVBQUFBLE1BQU0sRUFBRSxzQ0FqQlY7QUFrQkVELEVBQUFBLGdCQUFnQixFQUFFLHNDQWxCcEI7QUFtQkVSLEVBQUFBLElBQUksRUFBRSxzQ0FuQlI7QUFvQkVDLEVBQUFBLFNBQVMsRUFDUCxxSEFyQko7QUFzQkVFLEVBQUFBLEtBQUssRUFBRSxzQ0F0QlQ7QUF1QkVPLEVBQUFBLG1CQUFtQixFQUFFLE1BdkJ2QjtBQXdCRUwsRUFBQUEsT0FBTyxFQUFFLG9EQXhCWDtBQXlCRU0sRUFBQUEsY0FBYyxFQUFFLGVBekJsQjtBQTBCRUMsRUFBQUEsaUJBQWlCLEVBQUU7QUExQnJCLENBbCtCdUIsRUE4L0J2QjtBQUNFM0MsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLGFBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsQ0FMZDtBQU1FYSxFQUFBQSxPQUFPLEVBQUUsU0FOWDtBQU9FQyxFQUFBQSxRQUFRLEVBQUUsQ0FQWjtBQVFFQyxFQUFBQSxPQUFPLEVBQUUsQ0FSWDtBQVNFQyxFQUFBQSxRQUFRLEVBQUUsWUFUWjtBQVVFa0IsRUFBQUEsUUFBUSxFQUFFLEVBVlo7QUFXRVQsRUFBQUEsUUFBUSxFQUFFLG1EQVhaO0FBWUVSLEVBQUFBLE1BQU0sRUFBRSx3QkFaVjtBQWFFa0MsRUFBQUEsYUFBYSxFQUFFLHNDQWJqQjtBQWNFQyxFQUFBQSxXQUFXLEVBQUUsWUFkZjtBQWVFQyxFQUFBQSxRQUFRLEVBQUUsS0FmWjtBQWdCRVMsRUFBQUEsZ0JBQWdCLEVBQUUsc0NBaEJwQjtBQWlCRVIsRUFBQUEsSUFBSSxFQUFFLHNDQWpCUjtBQWtCRUMsRUFBQUEsU0FBUyxFQUFFLEVBbEJiO0FBbUJFRSxFQUFBQSxLQUFLLEVBQUUsc0NBbkJUO0FBb0JFdUIsRUFBQUEsd0JBQXdCLEVBQUUsRUFwQjVCO0FBcUJFaEIsRUFBQUEsbUJBQW1CLEVBQUUsRUFyQnZCO0FBc0JFaUIsRUFBQUEsbUJBQW1CLEVBQUUsZ0JBdEJ2QjtBQXVCRUMsRUFBQUEsc0JBQXNCLEVBQUUsMENBdkIxQjtBQXdCRXZCLEVBQUFBLE9BQU8sRUFBRSxvREF4Qlg7QUF5QkVNLEVBQUFBLGNBQWMsRUFBRSxnQkF6QmxCO0FBMEJFQyxFQUFBQSxpQkFBaUIsRUFBRTtBQTFCckIsQ0E5L0J1QixFQTBoQ3ZCO0FBQ0UzQyxFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUsb0JBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsQ0FMZDtBQU1FYSxFQUFBQSxPQUFPLEVBQUUsNkNBTlg7QUFPRUMsRUFBQUEsUUFBUSxFQUFFLENBUFo7QUFRRUMsRUFBQUEsT0FBTyxFQUFFLENBUlg7QUFTRUMsRUFBQUEsUUFBUSxFQUFFLFlBVFo7QUFVRWtCLEVBQUFBLFFBQVEsRUFBRSxjQVZaO0FBV0VULEVBQUFBLFFBQVEsRUFDTixrR0FaSjtBQWFFUixFQUFBQSxNQUFNLEVBQUUsZ0JBYlY7QUFjRWtDLEVBQUFBLGFBQWEsRUFBRSxzQ0FkakI7QUFlRUMsRUFBQUEsV0FBVyxFQUFFLFlBZmY7QUFnQkVDLEVBQUFBLFFBQVEsRUFBRSxNQWhCWjtBQWlCRUMsRUFBQUEsSUFBSSxFQUFFLHNDQWpCUjtBQWtCRUMsRUFBQUEsU0FBUyxFQUNQLHFIQW5CSjtBQW9CRUUsRUFBQUEsS0FBSyxFQUFFO0FBcEJULENBMWhDdUIsRUFnakN2QjtBQUNFbEMsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLGFBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsQ0FMZDtBQU1Fd0IsRUFBQUEsWUFBWSxFQUFFLE1BTmhCO0FBT0VYLEVBQUFBLE9BQU8sRUFBRSxpRUFQWDtBQVFFQyxFQUFBQSxRQUFRLEVBQUUsQ0FSWjtBQVNFQyxFQUFBQSxPQUFPLEVBQUUsQ0FUWDtBQVVFQyxFQUFBQSxRQUFRLEVBQUUsVUFWWjtBQVdFa0IsRUFBQUEsUUFBUSxFQUFFLHNCQVhaO0FBWUVULEVBQUFBLFFBQVEsRUFDTix1R0FiSjtBQWNFUixFQUFBQSxNQUFNLEVBQUUsaUVBZFY7QUFlRWtFLEVBQUFBLEtBQUssRUFBRSxzQ0FmVDtBQWdCRUMsRUFBQUEsV0FBVyxFQUFFLEVBaEJmO0FBaUJFQyxFQUFBQSxjQUFjLEVBQUUsSUFqQmxCO0FBa0JFQyxFQUFBQSxnQkFBZ0IsRUFBRSxxQkFsQnBCO0FBbUJFQyxFQUFBQSxpQkFBaUIsRUFBRSxnQ0FuQnJCO0FBb0JFeEQsRUFBQUEsVUFBVSxFQUFFLENBQ1Y7QUFDRTNDLElBQUFBLElBQUksRUFBRSxVQURSO0FBRUVDLElBQUFBLEtBQUssRUFDSDtBQUhKLEdBRFUsRUFNVjtBQUNFRCxJQUFBQSxJQUFJLEVBQUUsd0JBRFI7QUFFRUMsSUFBQUEsS0FBSyxFQUFFO0FBRlQsR0FOVSxFQVVWO0FBQ0VELElBQUFBLElBQUksRUFBRSxjQURSO0FBRUVDLElBQUFBLEtBQUssRUFBRTtBQUZULEdBVlUsRUFjVjtBQUNFRCxJQUFBQSxJQUFJLEVBQUUsT0FEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQUU7QUFGVCxHQWRVLEVBa0JWO0FBQ0VELElBQUFBLElBQUksRUFBRSxrQkFEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQUU7QUFGVCxHQWxCVSxFQXNCVjtBQUNFRCxJQUFBQSxJQUFJLEVBQUUsZ0JBRFI7QUFFRUMsSUFBQUEsS0FBSyxFQUNIO0FBSEosR0F0QlUsQ0FwQmQ7QUFnREVtRyxFQUFBQSxTQUFTLEVBQUU7QUFoRGIsQ0FoakN1QixFQWttQ3ZCO0FBQ0VqRSxFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUseUJBSGI7QUFJRUMsRUFBQUEsY0FBYyxFQUFFLHNDQUpsQjtBQUtFWixFQUFBQSxVQUFVLEVBQUUsQ0FMZDtBQU1Fd0IsRUFBQUEsWUFBWSxFQUFFLFdBTmhCO0FBT0VYLEVBQUFBLE9BQU8sRUFBRSxVQVBYO0FBUUVDLEVBQUFBLFFBQVEsRUFBRSxDQVJaO0FBU0VDLEVBQUFBLE9BQU8sRUFBRSxDQVRYO0FBVUVDLEVBQUFBLFFBQVEsRUFBRSxVQVZaO0FBV0VrQixFQUFBQSxRQUFRLEVBQUUsS0FYWjtBQVlFakIsRUFBQUEsTUFBTSxFQUFFLFVBWlY7QUFhRXdFLEVBQUFBLGVBQWUsRUFBRSxLQWJuQjtBQWNFQyxFQUFBQSxnQkFBZ0IsRUFBRSxpREFkcEI7QUFlRUwsRUFBQUEsY0FBYyxFQUFFLElBZmxCO0FBZ0JFTSxFQUFBQSxpQkFBaUIsRUFBRSxDQWhCckI7QUFpQkVDLEVBQUFBLFNBQVMsRUFBRSxDQWpCYjtBQWtCRUMsRUFBQUEsWUFBWSxFQUFFLFVBbEJoQjtBQW1CRUMsRUFBQUEsV0FBVyxFQUFFLHNDQW5CZjtBQW9CRUMsRUFBQUEsNEJBQTRCLEVBQUUsVUFwQmhDO0FBcUJFQyxFQUFBQSxlQUFlLEVBQUUsb0RBckJuQjtBQXNCRUMsRUFBQUEsZUFBZSxFQUFFLDBCQXRCbkI7QUF1QkVYLEVBQUFBLGdCQUFnQixFQUFFLHFCQXZCcEI7QUF3QkVDLEVBQUFBLGlCQUFpQixFQUFFLG9DQXhCckI7QUF5QkVXLEVBQUFBLElBQUksRUFBRTtBQUNKeEYsSUFBQUEsRUFBRSxFQUFFLGtFQURBO0FBRUp5RixJQUFBQSxZQUFZLEVBQUU7QUFDWnpGLE1BQUFBLEVBQUUsRUFBRSxrRUFEUTtBQUVaMEYsTUFBQUEsWUFBWSxFQUNWLHdHQUhVO0FBSVpDLE1BQUFBLFNBQVMsRUFBRSxxREFKQztBQUtaQyxNQUFBQSxTQUFTLEVBQUUsY0FMQztBQU1abEgsTUFBQUEsSUFBSSxFQUFFLFVBTk07QUFPWm1ILE1BQUFBLElBQUksRUFBRTtBQVBNO0FBRlY7QUF6QlIsQ0FsbUN1QixFQXdvQ3ZCO0FBQ0VoRixFQUFBQSxZQUFZLEVBQUUscUJBRGhCO0FBRUViLEVBQUFBLEVBQUUsRUFBRSxzQ0FGTjtBQUdFQyxFQUFBQSxTQUFTLEVBQUUsUUFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxDQUxkO0FBTUV3QixFQUFBQSxZQUFZLEVBQUUsV0FOaEI7QUFPRVgsRUFBQUEsT0FBTyxFQUFFLFVBUFg7QUFRRUMsRUFBQUEsUUFBUSxFQUFFLENBUlo7QUFTRUMsRUFBQUEsT0FBTyxFQUFFLENBVFg7QUFVRUMsRUFBQUEsUUFBUSxFQUFFLFVBVlo7QUFXRWtCLEVBQUFBLFFBQVEsRUFBRSxLQVhaO0FBWUVqQixFQUFBQSxNQUFNLEVBQUUsVUFaVjtBQWFFd0UsRUFBQUEsZUFBZSxFQUFFLEtBYm5CO0FBY0VDLEVBQUFBLGdCQUFnQixFQUFFLGlEQWRwQjtBQWVFTCxFQUFBQSxjQUFjLEVBQUUsSUFmbEI7QUFnQkVNLEVBQUFBLGlCQUFpQixFQUFFLENBaEJyQjtBQWlCRUMsRUFBQUEsU0FBUyxFQUFFLENBakJiO0FBa0JFQyxFQUFBQSxZQUFZLEVBQUUsVUFsQmhCO0FBbUJFQyxFQUFBQSxXQUFXLEVBQUUsc0NBbkJmO0FBb0JFQyxFQUFBQSw0QkFBNEIsRUFBRSxVQXBCaEM7QUFxQkVDLEVBQUFBLGVBQWUsRUFBRSxvREFyQm5CO0FBc0JFQyxFQUFBQSxlQUFlLEVBQUUsMEJBdEJuQjtBQXVCRVgsRUFBQUEsZ0JBQWdCLEVBQUUscUJBdkJwQjtBQXdCRUMsRUFBQUEsaUJBQWlCLEVBQUUsb0NBeEJyQjtBQXlCRVcsRUFBQUEsSUFBSSxFQUFFO0FBQ0pNLElBQUFBLFdBQVcsRUFDVCw4VEFGRTtBQUdKOUYsSUFBQUEsRUFBRSxFQUNBLGtHQUpFO0FBS0orRixJQUFBQSxpQkFBaUIsRUFDZixrRkFORTtBQU9KQyxJQUFBQSxRQUFRLEVBQUUsS0FQTjtBQVFKUCxJQUFBQSxZQUFZLEVBQUU7QUFDWnpGLE1BQUFBLEVBQUUsRUFBRSxrRUFEUTtBQUVaNkYsTUFBQUEsSUFBSSxFQUFFO0FBRk0sS0FSVjtBQVlKSSxJQUFBQSxPQUFPLEVBQUU7QUFaTDtBQXpCUixDQXhvQ3VCLEVBZ3JDdkI7QUFDRXBGLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSxxQkFIYjtBQUlFQyxFQUFBQSxjQUFjLEVBQUUsc0NBSmxCO0FBS0VaLEVBQUFBLFVBQVUsRUFBRSxDQUxkO0FBTUV3QixFQUFBQSxZQUFZLEVBQUUsTUFOaEI7QUFPRVgsRUFBQUEsT0FBTyxFQUFFLDZCQVBYO0FBUUVDLEVBQUFBLFFBQVEsRUFBRSxDQVJaO0FBU0VDLEVBQUFBLE9BQU8sRUFBRSxDQVRYO0FBVUVDLEVBQUFBLFFBQVEsRUFBRSxVQVZaO0FBV0VrQixFQUFBQSxRQUFRLEVBQUUsa0NBWFo7QUFZRVQsRUFBQUEsUUFBUSxFQUFFLHFEQVpaO0FBYUVSLEVBQUFBLE1BQU0sRUFBRSw2QkFiVjtBQWNFa0UsRUFBQUEsS0FBSyxFQUFFLHNDQWRUO0FBZUVDLEVBQUFBLFdBQVcsRUFBRSxzQ0FmZjtBQWdCRUMsRUFBQUEsY0FBYyxFQUFFLEtBaEJsQjtBQWlCRUMsRUFBQUEsZ0JBQWdCLEVBQUUscUJBakJwQjtBQWtCRUMsRUFBQUEsaUJBQWlCLEVBQUUsZ0NBbEJyQjtBQW1CRXhELEVBQUFBLFVBQVUsRUFBRSxDQUNWO0FBQ0UzQyxJQUFBQSxJQUFJLEVBQUUsVUFEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQUU7QUFGVCxHQURVLENBbkJkO0FBeUJFbUcsRUFBQUEsU0FBUyxFQUFFO0FBekJiLENBaHJDdUIsRUEyc0N2QjtBQUNFakUsRUFBQUEsWUFBWSxFQUFFLHFCQURoQjtBQUVFYixFQUFBQSxFQUFFLEVBQUUsc0NBRk47QUFHRUMsRUFBQUEsU0FBUyxFQUFFLGtCQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLENBTGQ7QUFNRXdCLEVBQUFBLFlBQVksRUFBRSxNQU5oQjtBQU9FWCxFQUFBQSxPQUFPLEVBQUUsaUVBUFg7QUFRRUMsRUFBQUEsUUFBUSxFQUFFLENBUlo7QUFTRUMsRUFBQUEsT0FBTyxFQUFFLENBVFg7QUFVRUMsRUFBQUEsUUFBUSxFQUFFLFVBVlo7QUFXRWtCLEVBQUFBLFFBQVEsRUFBRSxvQkFYWjtBQVlFVCxFQUFBQSxRQUFRLEVBQ04sbUtBYko7QUFjRVIsRUFBQUEsTUFBTSxFQUFFLGlFQWRWO0FBZUVrRSxFQUFBQSxLQUFLLEVBQUUsc0NBZlQ7QUFnQkVDLEVBQUFBLFdBQVcsRUFBRSxFQWhCZjtBQWlCRUMsRUFBQUEsY0FBYyxFQUFFLElBakJsQjtBQWtCRUMsRUFBQUEsZ0JBQWdCLEVBQUUscUJBbEJwQjtBQW1CRUMsRUFBQUEsaUJBQWlCLEVBQUUsa0NBbkJyQjtBQW9CRXhELEVBQUFBLFVBQVUsRUFBRSxDQUNWO0FBQ0UzQyxJQUFBQSxJQUFJLEVBQUUsVUFEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQ0g7QUFISixHQURVLEVBTVY7QUFDRUQsSUFBQUEsSUFBSSxFQUFFLGdCQURSO0FBRUVDLElBQUFBLEtBQUssRUFBRTtBQUZULEdBTlUsRUFVVjtBQUNFRCxJQUFBQSxJQUFJLEVBQUUsMkJBRFI7QUFFRUMsSUFBQUEsS0FBSyxFQUFFO0FBRlQsR0FWVSxDQXBCZDtBQW1DRW1HLEVBQUFBLFNBQVMsRUFBRTtBQW5DYixDQTNzQ3VCLEVBZ3ZDdkI7QUFDRWpFLEVBQUFBLFlBQVksRUFBRSxxQkFEaEI7QUFFRWIsRUFBQUEsRUFBRSxFQUFFLHNDQUZOO0FBR0VDLEVBQUFBLFNBQVMsRUFBRSxVQUhiO0FBSUVDLEVBQUFBLGNBQWMsRUFBRSxzQ0FKbEI7QUFLRVosRUFBQUEsVUFBVSxFQUFFLENBTGQ7QUFNRXdCLEVBQUFBLFlBQVksRUFBRSxNQU5oQjtBQU9FWCxFQUFBQSxPQUFPLEVBQUUsa0VBUFg7QUFRRUMsRUFBQUEsUUFBUSxFQUFFLENBUlo7QUFTRUMsRUFBQUEsT0FBTyxFQUFFLENBVFg7QUFVRUMsRUFBQUEsUUFBUSxFQUFFLFVBVlo7QUFXRVMsRUFBQUEsUUFBUSxFQUNOLHVHQVpKO0FBYUVSLEVBQUFBLE1BQU0sRUFBRSxrRUFiVjtBQWNFa0UsRUFBQUEsS0FBSyxFQUFFLEVBZFQ7QUFlRUMsRUFBQUEsV0FBVyxFQUFFLEVBZmY7QUFnQkVDLEVBQUFBLGNBQWMsRUFBRSxJQWhCbEI7QUFpQkVDLEVBQUFBLGdCQUFnQixFQUFFLHFCQWpCcEI7QUFrQkVDLEVBQUFBLGlCQUFpQixFQUFFLGdDQWxCckI7QUFtQkV4RCxFQUFBQSxVQUFVLEVBQUUsQ0FDVjtBQUNFM0MsSUFBQUEsSUFBSSxFQUFFLFVBRFI7QUFFRUMsSUFBQUEsS0FBSyxFQUFFO0FBRlQsR0FEVSxFQUtWO0FBQ0VELElBQUFBLElBQUksRUFBRSwwQkFEUjtBQUVFQyxJQUFBQSxLQUFLLEVBQUU7QUFGVCxHQUxVLEVBU1Y7QUFDRUQsSUFBQUEsSUFBSSxFQUFFLGFBRFI7QUFFRUMsSUFBQUEsS0FBSyxFQUFFO0FBRlQsR0FUVSxFQWFWO0FBQ0VELElBQUFBLElBQUksRUFBRSxlQURSO0FBRUVDLElBQUFBLEtBQUssRUFBRTtBQUZULEdBYlU7QUFuQmQsQ0FodkN1QixDQUFsQiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBPZmZpY2UzNjUgc2FtcGxlIGRhdGFcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5cbmV4cG9ydCBjb25zdCBhcnJheU9mZmljZUdyb3VwcyA9IFsnb2ZmaWNlMzY1JywgJ0F6dXJlQWN0aXZlRGlyZWN0b3J5U3RzTG9nb24nXTtcblxuZXhwb3J0IGNvbnN0IGFycmF5TG9jYXRpb25PZmZpY2UgPSAnb2ZmaWNlMzY1JztcblxuZXhwb3J0IGNvbnN0IGFycmF5RGVjb2Rlck9mZmljZSA9IFtcbiAge1xuICAgIG5hbWU6ICdqc29uJyxcbiAgfSxcbl07XG5cbmV4cG9ydCBjb25zdCBhcnJheVV1aWRPZmZpY2UgPSBbXG4gICdhODA4MDAwOS1hYTg1LTRkNjUtYTBmMC03NGZlMDMzMWVkY2UnLFxuICAnNGU5M2M4ZTMtNTJjMS00YTRlLWFiNjktOWU2MWNjZjZjZDAwJyxcbiAgJ2QxNGFhNWNiLWIwNzAtNDJmOC04NzA5LTBmOGFmZDk0MmZjMCcsXG4gICc5MmE3ZTg5My0wZjRhLTQ2MzUtYWYwZC04Mzg5MWQ0ZmY5YzAnLFxuICAnY2UwMTNmMDUtYTc4My00MTg2LTlkODUtNWExNDk5OGI2MTExJyxcbiAgJzRmNjg2ZTAzLTdjZjYtNDRhOC05MjEyLWI4YTkxYjEyODA4MicsXG4gICdjYzU4ZTgxNy1jNmQzLTQ0NTctYjAxMS01NGU4ODFlMjMwZWMnLFxuICAnODI1ZjlkNmUtMTJjMC00YjU5LTgwN2QtMWI0MWM2ZTQ4YTNhJyxcbiAgJ2QzNjI1M2ZiLTI0YTEtNDgxYy1hMTk5LWY3Nzg1MzRjY2I1ZicsXG4gICc5MDgzMzY5ZS02NzliLTRlOGItOTI0OS0zMjNhNTFkNWJmOWMnLFxuICAnNmQ4NzJiZjgtZTQ2Mi00ZGU4LTllMTYtYzM2NzYxMDUwZmI3JyxcbiAgJ2I5YTczYzBmLTU1ZjItNGU5NS05NjI2LTFjMjY0ZDAyZWFjMycsXG4gICdiYmFiOTFhZC1iYzhhLTRjODYtOTAxMC0zYzg0YjM5ZmRlMGQnLFxuICAnYjUzNTkwOTItZGFkMi00MDYwLWI5M2QtMzc5MWU0ZGEwZGVjJyxcbiAgJ2U4NDkzYjI2LWMxZjktNDJlYi05NzU2LWRmZDM2MzE0OTg1MicsXG4gICdjYTIwNDRmYy0zMmNhLTQ3OGItOGIwZC1mZjZmZGQzYjFlNWEnLFxuICAnYTA5OTUxMzYtOTFkOC00YWNmLTg0NDktMjhjMjc1ZmZiN2UzJyxcbiAgJ2MzNDgyYjVkLWIxYTktNGY0NC04ZGYwLWE2MDFlMThjZjVjMycsXG4gICc0OWZkNDY0Mi1jZmU1LTQxNzAtOTQ4OC0yNWQ4NDdlMzU3OWYnLFxuICAnMjlmOTYyNzEtNWMxYi00N2VjLTk2NTItYTQxZDVjYjE3Y2I0Jyxcbl07XG5cbmV4cG9ydCBjb25zdCBhcnJheURldmljZVByb3BlcnRpZXNPZmZpY2UgPSBbXG4gIHtcbiAgICBOYW1lOiAnQnJvd3NlclR5cGUnLFxuICAgIFZhbHVlOiAnQ2hyb21lJyxcbiAgfSxcbiAge1xuICAgIE5hbWU6ICdJc0NvbXBsaWFudEFuZE1hbmFnZWQnLFxuICAgIFZhbHVlOiAnRmFsc2UnLFxuICB9LFxuICB7XG4gICAgTmFtZTogJ1Nlc3Npb25JZCcsXG4gICAgVmFsdWU6ICcyYTFmYjhjNC1jZWI2LTRmYTAtODI2Yy0zZDQzZjg3ZGU4OTcnLFxuICB9LFxuXTtcblxuZXhwb3J0IGNvbnN0IGFycmF5SXAgPSBbXG4gICc3Ny4yMzEuMTgyLjE3JyxcbiAgJzE3Mi4yMTcuMjA0Ljk0JyxcbiAgJzEwOC4xNzcuMTMuMTAxJyxcbiAgJzEzLjIyNi41Mi42NicsXG4gICcxMy4yMjYuNTIuMicsXG4gICcxMy4yMjYuNTIuMTA0JyxcbiAgJzEzLjIyNi41Mi44OScsXG4gICcxNDAuODIuMTEzLjMnLFxuXTtcbmV4cG9ydCBjb25zdCBhcnJheVVzZXJJZCA9IFtcbiAgJ3NtaXRoQHdhenVoLmNvbScsXG4gICd3aWxsaWFtc0B3YXp1aC5jb20nLFxuICAnZnJhbmtAd2F6dWguY29tJyxcbiAgJ2pvbmVzQHdhenVoLmNvbScsXG4gICdicm93bkB3YXp1aC5jb20nLFxuXTtcbmV4cG9ydCBjb25zdCBhcnJheVRhcmdldE9mZmljZSA9IFtcbiAge1xuICAgIElEOiAnNzk3ZjQ4NDYtYmEwMC00ZmQ3LWJhNDMtZGFjMWY4ZjYzMDEzJyxcbiAgICBUeXBlOiAwLFxuICB9LFxuXTtcblxuZXhwb3J0IGNvbnN0IGFycmF5QWN0b3JPZmZpY2UgPSBbXG4gIHtcbiAgICBJRDogJ2EzOWRkOTU3LWQyOTUtNDU0OC1iNTM3LTIwNTU0NjliYWZiYicsXG4gICAgVHlwZTogMCxcbiAgfSxcbiAge1xuICAgIElEOiAnYWxiZUB3YXp1aC5jb20nLFxuICAgIFR5cGU6IDUsXG4gIH0sXG5dO1xuXG5leHBvcnQgY29uc3QgYXJyYXlFeHRlbmRlZFByb3BlcnRpZXNPZmZpY2UgPSBbXG4gIHtcbiAgICBOYW1lOiAnUmVzdWx0U3RhdHVzRGV0YWlsJyxcbiAgICBWYWx1ZTogJ1N1Y2Nlc3MnLFxuICB9LFxuICB7XG4gICAgTmFtZTogJ1VzZXJBZ2VudCcsXG4gICAgVmFsdWU6XG4gICAgICAnTW96aWxsYS81LjAgKFgxMTsgTGludXggeDg2XzY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvOTEuMC40NDcyLjc3IFNhZmFyaS81MzcuMzYnLFxuICB9LFxuICB7XG4gICAgTmFtZTogJ1JlcXVlc3RUeXBlJyxcbiAgICBWYWx1ZTogJ09BdXRoMjpBdXRob3JpemUnLFxuICB9LFxuXTtcblxuZXhwb3J0IGNvbnN0IG9mZmljZVJ1bGVzID0ge1xuICAxOiB7XG4gICAgZGF0YToge1xuICAgICAgb2ZmaWNlMzY1OiB7XG4gICAgICAgIFJlY29yZFR5cGU6IDEsXG4gICAgICAgIFN1YnNjcmlwdGlvbjogJ0F1ZGl0LkV4Y2hhbmdlJyxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBydWxlOiB7XG4gICAgICBsZXZlbDogMyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnT2ZmaWNlIDM2NTogRXZlbnRzIGZyb20gdGhlIEV4Y2hhbmdlIGFkbWluIGF1ZGl0IGxvZy4nLFxuICAgICAgaWQ6ICc5MTUzMycsXG4gICAgICBtYWlsOiBmYWxzZSxcbiAgICAgIGZpcmVkdGltZXM6IDMsXG4gICAgICBncm91cHM6IFsnb2ZmaWNlMzY1JywgJ0V4Y2hhbmdlQWRtaW4nLCAnaGlwYWFfMTY0LjMxMi5iJywgJ3BjaV9kc3NfMTAuMi4yJywgJ3BjaV9kc3NfMTAuNi4xJ10sXG4gICAgfSxcbiAgfSxcbiAgMjoge1xuICAgIGRhdGE6IHtcbiAgICAgIG9mZmljZTM2NToge1xuICAgICAgICBSZWNvcmRUeXBlOiAyLFxuICAgICAgICBTdWJzY3JpcHRpb246ICdBdWRpdC5FeGNoYW5nZScsXG4gICAgICB9LFxuICAgIH0sXG4gICAgcnVsZToge1xuICAgICAgbGV2ZWw6IDMsXG4gICAgICBkZXNjcmlwdGlvbjpcbiAgICAgICAgJ09mZmljZSAzNjU6IEV2ZW50cyBmcm9tIGFuIEV4Y2hhbmdlIG1haWxib3ggYXVkaXQgbG9nIGZvciBhY3Rpb25zIHRoYXQgYXJlIHBlcmZvcm1lZCBvbiBhIHNpbmdsZSBpdGVtLCBzdWNoIGFzIGNyZWF0aW5nIG9yIHJlY2VpdmluZyBhbiBlbWFpbCBtZXNzYWdlLicsXG4gICAgICBpZDogJzkxNTM0JyxcbiAgICAgIG1haWw6IGZhbHNlLFxuICAgICAgZmlyZWR0aW1lczogMyxcbiAgICAgIGdyb3VwczogWydvZmZpY2UzNjUnLCAnRXhjaGFuZ2VJdGVtJywgJ2hpcGFhXzE2NC4zMTIuYicsICdwY2lfZHNzXzEwLjYuMiddLFxuICAgIH0sXG4gIH0sXG4gIDQ6IHtcbiAgICBkYXRhOiB7XG4gICAgICBvZmZpY2UzNjU6IHtcbiAgICAgICAgUmVjb3JkVHlwZTogNCxcbiAgICAgICAgU3Vic2NyaXB0aW9uOiAnQXVkaXQuU2hhcmVQb2ludCcsXG4gICAgICB9LFxuICAgIH0sXG4gICAgcnVsZToge1xuICAgICAgbGV2ZWw6IDMsXG4gICAgICBkZXNjcmlwdGlvbjogJ09mZmljZSAzNjU6IFNoYXJlUG9pbnQgZXZlbnRzLicsXG4gICAgICBpZDogJzkxNTM2JyxcbiAgICAgIG1haWw6IGZhbHNlLFxuICAgICAgZmlyZWR0aW1lczogMyxcbiAgICAgIGdyb3VwczogWydvZmZpY2UzNjUnLCAnU2hhcmVQb2ludCcsICdoaXBhYV8xNjQuMzEyLmInLCAncGNpX2Rzc18xMC42LjInXSxcbiAgICB9LFxuICB9LFxuICA2OiB7XG4gICAgZGF0YToge1xuICAgICAgb2ZmaWNlMzY1OiB7XG4gICAgICAgIFJlY29yZFR5cGU6IDYsXG4gICAgICAgIFN1YnNjcmlwdGlvbjogJ0F1ZGl0LlNoYXJlUG9pbnQnLFxuICAgICAgfSxcbiAgICB9LFxuICAgIHJ1bGU6IHtcbiAgICAgIGxldmVsOiAzLFxuICAgICAgZGVzY3JpcHRpb246ICdPZmZpY2UgMzY1OiBTaGFyZVBvaW50IGZpbGUgb3BlcmF0aW9uIGV2ZW50cy4nLFxuICAgICAgaWQ6ICc5MTUzNycsXG4gICAgICBtYWlsOiBmYWxzZSxcbiAgICAgIGZpcmVkdGltZXM6IDMsXG4gICAgICBncm91cHM6IFtcbiAgICAgICAgJ29mZmljZTM2NScsXG4gICAgICAgICdTaGFyZVBvaW50RmlsZU9wZXJhdGlvbicsXG4gICAgICAgICdoaXBhYV8xNjQuMzEyLmInLFxuICAgICAgICAnaGlwYWFfMTY0LjMxMi5jLjEnLFxuICAgICAgICAncGNpX2Rzc18xMC42LjInLFxuICAgICAgICAncGNpX2Rzc18xMS41JyxcbiAgICAgIF0sXG4gICAgfSxcbiAgfSxcbiAgODoge1xuICAgIGRhdGE6IHtcbiAgICAgIG9mZmljZTM2NToge1xuICAgICAgICBSZWNvcmRUeXBlOiA4LFxuICAgICAgICBTdWJzY3JpcHRpb246ICdBdWRpdC5BenVyZUFjdGl2ZURpcmVjdG9yeScsXG4gICAgICB9LFxuICAgIH0sXG4gICAgcnVsZToge1xuICAgICAgbGV2ZWw6IDMsXG4gICAgICBkZXNjcmlwdGlvbjogJ09mZmljZSAzNjU6IEF6dXJlIEFjdGl2ZSBEaXJlY3RvcnkgZXZlbnRzLicsXG4gICAgICBpZDogJzkxNTM5JyxcbiAgICAgIG1haWw6IGZhbHNlLFxuICAgICAgZmlyZWR0aW1lczogMyxcbiAgICAgIGdyb3VwczogWydvZmZpY2UzNjUnLCAnQXp1cmVBY3RpdmVEaXJlY3RvcnknLCAnaGlwYWFfMTY0LjMxMi5iJywgJ3BjaV9kc3NfMTAuNi4yJ10sXG4gICAgfSxcbiAgfSxcbiAgMTQ6IHtcbiAgICBkYXRhOiB7XG4gICAgICBvZmZpY2UzNjU6IHtcbiAgICAgICAgUmVjb3JkVHlwZTogMTQsXG4gICAgICAgIFN1YnNjcmlwdGlvbjogJ0F1ZGl0LlNoYXJlUG9pbnQnLFxuICAgICAgfSxcbiAgICB9LFxuICAgIHJ1bGU6IHtcbiAgICAgIGxldmVsOiAzLFxuICAgICAgZGVzY3JpcHRpb246ICdPZmZpY2UgMzY1OiBTaGFyZVBvaW50IHNoYXJpbmcgZXZlbnRzLicsXG4gICAgICBpZDogJzkxNTQ0JyxcbiAgICAgIG1haWw6IGZhbHNlLFxuICAgICAgZmlyZWR0aW1lczogMyxcbiAgICAgIGdyb3VwczogWydvZmZpY2UzNjUnLCAnU2hhcmVQb2ludCcsICdoaXBhYV8xNjQuMzEyLmInLCAncGNpX2Rzc18xMC42LjInXSxcbiAgICB9LFxuICB9LFxuICAxNToge1xuICAgIGRhdGE6IHtcbiAgICAgIG9mZmljZTM2NToge1xuICAgICAgICBSZWNvcmRUeXBlOiAxNSxcbiAgICAgICAgU3Vic2NyaXB0aW9uOiAnQXVkaXQuQXp1cmVBY3RpdmVEaXJlY3RvcnknLFxuICAgICAgfSxcbiAgICB9LFxuICAgIHJ1bGU6IHtcbiAgICAgIGxldmVsOiAzLFxuICAgICAgZGVzY3JpcHRpb246ICdPZmZpY2UgMzY1OiBTZWN1cmUgVG9rZW4gU2VydmljZSAoU1RTKSBsb2dvbiBldmVudHMgaW4gQXp1cmUgQWN0aXZlIERpcmVjdG9yeS4nLFxuICAgICAgaWQ6ICc5MTU0NScsXG4gICAgICBtYWlsOiBmYWxzZSxcbiAgICAgIGZpcmVkdGltZXM6IDMsXG4gICAgICBncm91cHM6IFtcbiAgICAgICAgJ29mZmljZTM2NScsXG4gICAgICAgICdBenVyZUFjdGl2ZURpcmVjdG9yeVN0c0xvZ29uJyxcbiAgICAgICAgJ2hpcGFhXzE2NC4zMTIuYS4yLkksaGlwYWFfMTY0LjMxMi5iJyxcbiAgICAgICAgJ2hpcGFhXzE2NC4zMTIuZCcsXG4gICAgICAgICdoaXBhYV8xNjQuMzEyLmUuMi5JSScsXG4gICAgICAgICdwY2lfZHNzXzguMyxwY2lfZHNzXzEwLjYuMScsXG4gICAgICBdLFxuICAgIH0sXG4gIH0sXG4gIDE4OiB7XG4gICAgZGF0YToge1xuICAgICAgb2ZmaWNlMzY1OiB7XG4gICAgICAgIFJlY29yZFR5cGU6IDE4LFxuICAgICAgICBTdWJzY3JpcHRpb246ICdBdWRpdC5HZW5lcmFsJyxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBydWxlOiB7XG4gICAgICBsZXZlbDogNSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnT2ZmaWNlIDM2NTogQWRtaW4gYWN0aW9ucyBmcm9tIHRoZSBTZWN1cml0eSBhbmQgQ29tcGxpYW5jZSBDZW50ZXIuJyxcbiAgICAgIGlkOiAnOTE1NDgnLFxuICAgICAgbWFpbDogZmFsc2UsXG4gICAgICBmaXJlZHRpbWVzOiAzLFxuICAgICAgZ3JvdXBzOiBbXG4gICAgICAgICdvZmZpY2UzNjUnLFxuICAgICAgICAnU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyRU9QQ21kbGV0JyxcbiAgICAgICAgJ2hpcGFhXzE2NC4zMTIuYicsXG4gICAgICAgICdwY2lfZHNzXzEwLjIuMicsXG4gICAgICAgICdwY2lfZHNzXzEwLjYuMScsXG4gICAgICBdLFxuICAgIH0sXG4gIH0sXG4gIDM2OiB7XG4gICAgZGF0YToge1xuICAgICAgb2ZmaWNlMzY1OiB7XG4gICAgICAgIFJlY29yZFR5cGU6IDM2LFxuICAgICAgICBTdWJzY3JpcHRpb246ICdBdWRpdC5TaGFyZVBvaW50JyxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBydWxlOiB7XG4gICAgICBsZXZlbDogMyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnT2ZmaWNlIDM2NTogU2hhcmVQb2ludCBMaXN0IGV2ZW50cy4nLFxuICAgICAgaWQ6ICc5MTU2NCcsXG4gICAgICBtYWlsOiBmYWxzZSxcbiAgICAgIGZpcmVkdGltZXM6IDMsXG4gICAgICBncm91cHM6IFsnb2ZmaWNlMzY1JywgJ1NoYXJlUG9pbnRMaXN0T3BlcmF0aW9uJywgJ2hpcGFhXzE2NC4zMTIuYicsICdwY2lfZHNzXzEwLjYuMiddLFxuICAgIH0sXG4gIH0sXG4gIDUyOiB7XG4gICAgZGF0YToge1xuICAgICAgb2ZmaWNlMzY1OiB7XG4gICAgICAgIFJlY29yZFR5cGU6IDUyLFxuICAgICAgICBTdWJzY3JpcHRpb246ICdBdWRpdC5HZW5lcmFsJyxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBydWxlOiB7XG4gICAgICBsZXZlbDogMyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnT2ZmaWNlIDM2NTogRGF0YSBJbnNpZ2h0cyBSRVNUIEFQSSBldmVudHMuJyxcbiAgICAgIGlkOiAnOTE1ODAnLFxuICAgICAgbWFpbDogZmFsc2UsXG4gICAgICBmaXJlZHRpbWVzOiA0LFxuICAgICAgZ3JvdXBzOiBbJ29mZmljZTM2NScsICdEYXRhSW5zaWdodHNSZXN0QXBpQXVkaXQnLCAnaGlwYWFfMTY0LjMxMi5iJywgJ3BjaV9kc3NfMTAuNi4yJ10sXG4gICAgfSxcbiAgfSxcbn07XG5leHBvcnQgY29uc3QgYXJyYXlMb2dzID0gW1xuICB7XG4gICAgSWQ6ICczNWFiOGI4OS1jZmVhLTQyMTQtNTI0OS0wOGQ5MWEwNmU1MzcnLFxuICAgIE9wZXJhdGlvbjogJ1NlYXJjaERhdGFJbnNpZ2h0c1N1YnNjcmlwdGlvbicsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDUyLFxuICAgIFVzZXJLZXk6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgVXNlclR5cGU6IDUsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ1NlY3VyaXR5Q29tcGxpYW5jZUNlbnRlcicsXG4gICAgVXNlcklkOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIEFhZEFwcElkOiAnODBjY2NhNjctNTRiZC00NGFiLTg2MjUtNGI3OWM0ZGM3Nzc1JyxcbiAgICBEYXRhVHlwZTogJ0RhdGFJbnNpZ2h0c1N1YnNjcmlwdGlvbicsXG4gICAgRGF0YWJhc2VUeXBlOiAnRGlyZWN0b3J5JyxcbiAgICBSZWxhdGl2ZVVybDpcbiAgICAgICcvRGF0YUluc2lnaHRzL0RhdGFJbnNpZ2h0c1NlcnZpY2Uuc3ZjL0ZpbmQvRGF0YUluc2lnaHRzU3Vic2NyaXB0aW9uP3RlbmFudGlkPTBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVzdWx0Q291bnQ6ICcxJyxcbiAgfSxcbiAge1xuICAgIElkOiAnMjdlZTJlOTUtNmY1NS00NzIzLWY5MWQtMDhkOTFhMjZiOWE0JyxcbiAgICBPcGVyYXRpb246ICdTZWFyY2hBbGVydCcsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDUyLFxuICAgIFVzZXJLZXk6ICc5MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgIFVzZXJUeXBlOiAwLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTZWN1cml0eUNvbXBsaWFuY2VDZW50ZXInLFxuICAgIFVzZXJJZDogJzkxMGVkNWNhLTRlY2YtNDE0Yy1hMWJlLWQ1MzUxMWJmZTFhNScsXG4gICAgQWFkQXBwSWQ6ICdmYzc4MDQ2NS0yMDE3LTQwZDQtYTBjNS0zMDcwMjI0NzFiOTInLFxuICAgIERhdGFUeXBlOiAnQWxlcnQnLFxuICAgIERhdGFiYXNlVHlwZTogJ0RhdGFJbnNpZ2h0cycsXG4gICAgUmVsYXRpdmVVcmw6XG4gICAgICAnL0RhdGFJbnNpZ2h0cy9EYXRhSW5zaWdodHNTZXJ2aWNlLnN2Yy9GaW5kL0FsZXJ0P3RlbmFudGlkPTBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YiZQYWdlU2l6ZT0xMDAmRmlsdGVyPVN0YXJ0RGF0ZStlcSsyMDIxLTA0LTE4VDE3JTNhNTklM2E0MC44ODIwNjU1WithbmQrRW5kRGF0ZStlcSsyMDIxLTA1LTE4VDE3JTNhNTklM2E0MC44ODIwNjU1WithbmQrQWxlcnRDYXRlZ29yeSthbnkrMSUyYzMlMmM3JTJjNSUyYzQrYW5kK0FsZXJ0U291cmNlK2VxKyUyN09mZmljZSszNjUrU2VjdXJpdHkrJTI2K0NvbXBsaWFuY2UlMjcnLFxuICAgIFJlc3VsdENvdW50OiAnMCcsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTE4VDE3OjU5OjUyJyxcbiAgICBJZDogJzdkM2E5ZDM1LTZjMDQtNGYwMi1lOGZlLTA4ZDkxYTI2YmM3OScsXG4gICAgT3BlcmF0aW9uOiAnU2VhcmNoQWxlcnRBZ2dyZWdhdGUnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiA1MixcbiAgICBVc2VyS2V5OiAnOTEwZWQ1Y2EtNGVjZi00MTRjLWExYmUtZDUzNTExYmZlMWE1JyxcbiAgICBVc2VyVHlwZTogMCxcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyJyxcbiAgICBVc2VySWQ6ICc5MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgIEFhZEFwcElkOiAnZmM3ODA0NjUtMjAxNy00MGQ0LWEwYzUtMzA3MDIyNDcxYjkyJyxcbiAgICBEYXRhVHlwZTogJ0FsZXJ0QWdncmVnYXRlJyxcbiAgICBEYXRhYmFzZVR5cGU6ICdEYXRhSW5zaWdodHMnLFxuICAgIFJlbGF0aXZlVXJsOlxuICAgICAgJy9EYXRhSW5zaWdodHMvRGF0YUluc2lnaHRzU2VydmljZS5zdmMvRmluZC9BbGVydEFnZ3JlZ2F0ZT90ZW5hbnRpZD0wZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWImUGFnZVNpemU9NTQwJkZpbHRlcj1TdGFydERhdGUrZXErMjAyMS0wNC0xOFQxNyUzYTU5JTNhNDguMzUwNDA1MForYW5kK0VuZERhdGUrZXErMjAyMS0wNS0xOFQxNyUzYTU5JTNhNDguMzUwNDA1MForYW5kK0FsZXJ0Q2F0ZWdvcnkrYW55KzElMmMzJTJjNyUyYzUlMmM0K2FuZCtBbGVydFNvdXJjZStlcSslMjdPZmZpY2UrMzY1K1NlY3VyaXR5KyUyNitDb21wbGlhbmNlJTI3JyxcbiAgICBSZXN1bHRDb3VudDogJzAnLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0xOFQxNzo1OTo0NicsXG4gICAgSWQ6ICdlYjk3NzVjYi01OWY3LTQyZWEtM2VlMC0wOGQ5MWEyNmI5MmInLFxuICAgIE9wZXJhdGlvbjogJ1ZhbGlkYXRlcmJhY0FjY2Vzc0NoZWNrJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogNTIsXG4gICAgVXNlcktleTogJ2Zha2VAZW1haWwubm90JyxcbiAgICBVc2VyVHlwZTogNSxcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyJyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgQWFkQXBwSWQ6ICdkNmZkYWEzMy1lODIxLTQyMTEtODNkMC1jZjc0NzM2NDg5ZTEnLFxuICAgIERhdGFUeXBlOiAncmJhY0FjY2Vzc0NoZWNrJyxcbiAgICBSZWxhdGl2ZVVybDpcbiAgICAgICcvRGF0YUluc2lnaHRzL0RhdGFJbnNpZ2h0c1NlcnZpY2Uuc3ZjL3ZhbGlkYXRlL3JiYWNBY2Nlc3NDaGVjaz90ZW5hbnRpZD0wZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlc3VsdENvdW50OiAnMCcsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTE4VDE0OjEyOjUzJyxcbiAgICBJZDogJ2MwZWFkYTFiLTUyYjItNDUwZC04NGRmLTZkNDYxNDIwZDYyMScsXG4gICAgT3BlcmF0aW9uOiAnR2V0LVJldGVudGlvbkNvbXBsaWFuY2VQb2xpY3knLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiAxOCxcbiAgICBSZXN1bHRTdGF0dXM6ICdTdWNjZXNzJyxcbiAgICBVc2VyS2V5OiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIFVzZXJUeXBlOiAyLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTZWN1cml0eUNvbXBsaWFuY2VDZW50ZXInLFxuICAgIE9iamVjdElkOiAnJyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyRXZlbnRUeXBlOiAwLFxuICAgIENsaWVudEFwcGxpY2F0aW9uOiAnRU1DJyxcbiAgICBDbWRsZXRWZXJzaW9uOiAnLi4uJyxcbiAgICBFZmZlY3RpdmVPcmdhbml6YXRpb246ICd3YXp1aC50ZXN0eXRlc3QuY29tJyxcbiAgICBOb25QSUlQYXJhbWV0ZXJzOiAnJyxcbiAgICBQYXJhbWV0ZXJzOiAnJyxcbiAgICBTdGFydFRpbWU6ICcyMDIxLTA1LTE4VDE0OjEyOjUzJyxcbiAgICBVc2VyU2VydmljZVBsYW46ICcnLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0xOFQxNTo1MjoyNicsXG4gICAgSWQ6ICc0NWEwZDdjNC1kZTczLTQ2NmEtOGU2Yy1jMjVmOWMwMzU3MTQnLFxuICAgIE9wZXJhdGlvbjogJ0dldC1TdXBlcnZpc29yeVJldmlld1BvbGljeVYyJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogMTgsXG4gICAgUmVzdWx0U3RhdHVzOiAnU3VjY2VzcycsXG4gICAgVXNlcktleTogJ2Zha2VAZW1haWwubm90JyxcbiAgICBVc2VyVHlwZTogMixcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyJyxcbiAgICBPYmplY3RJZDogJycsXG4gICAgVXNlcklkOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIFNlY3VyaXR5Q29tcGxpYW5jZUNlbnRlckV2ZW50VHlwZTogMCxcbiAgICBDbGllbnRBcHBsaWNhdGlvbjogJ0VNQycsXG4gICAgQ21kbGV0VmVyc2lvbjogJy4uLicsXG4gICAgRWZmZWN0aXZlT3JnYW5pemF0aW9uOiAnd2F6dWgudGVzdHl0ZXN0LmNvbScsXG4gICAgTm9uUElJUGFyYW1ldGVyczogJycsXG4gICAgUGFyYW1ldGVyczogJycsXG4gICAgU3RhcnRUaW1lOiAnMjAyMS0wNS0xOFQxNTo1MjoyNicsXG4gICAgVXNlclNlcnZpY2VQbGFuOiAnJyxcbiAgfSxcbiAge1xuICAgIENyZWF0aW9uVGltZTogJzIwMjEtMDUtMThUMTU6NTI6MzEnLFxuICAgIElkOiAnZjk5MTI4NjgtYjQzMS00MzVjLTgzMzctMGZjM2I0MzcwODE1JyxcbiAgICBPcGVyYXRpb246ICdHZXQtU3VwZXJ2aXNvcnlSZXZpZXdSZXBvcnQnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiAxOCxcbiAgICBSZXN1bHRTdGF0dXM6ICdTdWNjZXNzJyxcbiAgICBVc2VyS2V5OiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIFVzZXJUeXBlOiAyLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTZWN1cml0eUNvbXBsaWFuY2VDZW50ZXInLFxuICAgIE9iamVjdElkOiAnJyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyRXZlbnRUeXBlOiAwLFxuICAgIENsaWVudEFwcGxpY2F0aW9uOiAnRU1DJyxcbiAgICBDbWRsZXRWZXJzaW9uOiAnLi4uJyxcbiAgICBFZmZlY3RpdmVPcmdhbml6YXRpb246ICd3YXp1aC50ZXN0eXRlc3QuY29tJyxcbiAgICBOb25QSUlQYXJhbWV0ZXJzOlxuICAgICAgJy1TdGFydERhdGUgXCI8U05JUC1QSUk+XCIgLUVuZERhdGUgXCI8U05JUC1QSUk+XCIgLVBhZ2VTaXplIFwiPFNOSVAtUElJPlwiIC1QYWdlIFwiPFNOSVAtUElJPlwiJyxcbiAgICBQYXJhbWV0ZXJzOlxuICAgICAgJy1TdGFydERhdGUgXCI1LzEyLzIwMjEgMTI6MDA6MDAgQU1cIiAtRW5kRGF0ZSBcIjUvMTgvMjAyMSAxMTo1OTo1OSBQTVwiIC1QYWdlU2l6ZSBcIjMwMFwiIC1QYWdlIFwiMVwiJyxcbiAgICBTdGFydFRpbWU6ICcyMDIxLTA1LTE4VDE1OjUyOjMxJyxcbiAgICBVc2VyU2VydmljZVBsYW46ICcnLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0xOFQxNTo1MjozMCcsXG4gICAgSWQ6ICdkY2VjZDg3YS0zMDYxLTRkZWEtOWJmZi00ZmJmYzIzY2EzMjgnLFxuICAgIE9wZXJhdGlvbjogJ0dldC1TdXBlcnZpc29yeVJldmlld092ZXJhbGxQcm9ncmVzc1JlcG9ydCcsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDE4LFxuICAgIFJlc3VsdFN0YXR1czogJ1N1Y2Nlc3MnLFxuICAgIFVzZXJLZXk6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgVXNlclR5cGU6IDIsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ1NlY3VyaXR5Q29tcGxpYW5jZUNlbnRlcicsXG4gICAgT2JqZWN0SWQ6ICcnLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBTZWN1cml0eUNvbXBsaWFuY2VDZW50ZXJFdmVudFR5cGU6IDAsXG4gICAgQ2xpZW50QXBwbGljYXRpb246ICdFTUMnLFxuICAgIENtZGxldFZlcnNpb246ICcuLi4nLFxuICAgIEVmZmVjdGl2ZU9yZ2FuaXphdGlvbjogJ3dhenVoLnRlc3R5dGVzdC5jb20nLFxuICAgIE5vblBJSVBhcmFtZXRlcnM6ICcnLFxuICAgIFBhcmFtZXRlcnM6ICcnLFxuICAgIFN0YXJ0VGltZTogJzIwMjEtMDUtMThUMTU6NTI6MzAnLFxuICAgIFVzZXJTZXJ2aWNlUGxhbjogJycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTE4VDE1OjUyOjMwJyxcbiAgICBJZDogJzU2NDFkMDYyLWYyNzktNGNhNC05NTc3LTUwZDdlY2JmZWVkYicsXG4gICAgT3BlcmF0aW9uOiAnR2V0LVN1cGVydmlzb3J5UmV2aWV3VG9wQ2FzZXNSZXBvcnQnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiAxOCxcbiAgICBSZXN1bHRTdGF0dXM6ICdTdWNjZXNzJyxcbiAgICBVc2VyS2V5OiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIFVzZXJUeXBlOiAyLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTZWN1cml0eUNvbXBsaWFuY2VDZW50ZXInLFxuICAgIE9iamVjdElkOiAnJyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyRXZlbnRUeXBlOiAwLFxuICAgIENsaWVudEFwcGxpY2F0aW9uOiAnRU1DJyxcbiAgICBDbWRsZXRWZXJzaW9uOiAnLi4uJyxcbiAgICBFZmZlY3RpdmVPcmdhbml6YXRpb246ICd3YXp1aC50ZXN0eXRlc3QuY29tJyxcbiAgICBOb25QSUlQYXJhbWV0ZXJzOiAnJyxcbiAgICBQYXJhbWV0ZXJzOiAnJyxcbiAgICBTdGFydFRpbWU6ICcyMDIxLTA1LTE4VDE1OjUyOjMwJyxcbiAgICBVc2VyU2VydmljZVBsYW46ICcnLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0xOFQxNzo1MDoxNScsXG4gICAgSWQ6ICc4YzdjOWY4MS02OGU5LTQ1MmItYTIyZC0xMzMzZWI5Y2Q2NDcnLFxuICAgIE9wZXJhdGlvbjogJ0dldC1Db21wbGlhbmNlU2VhcmNoQWN0aW9uJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogMTgsXG4gICAgUmVzdWx0U3RhdHVzOiAnU3VjY2VzcycsXG4gICAgVXNlcktleTogJ2Zha2VAZW1haWwubm90JyxcbiAgICBVc2VyVHlwZTogMixcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyJyxcbiAgICBPYmplY3RJZDogJycsXG4gICAgVXNlcklkOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIFNlY3VyaXR5Q29tcGxpYW5jZUNlbnRlckV2ZW50VHlwZTogMCxcbiAgICBDbGllbnRBcHBsaWNhdGlvbjogJ0VNQycsXG4gICAgQ21kbGV0VmVyc2lvbjogJy4uLicsXG4gICAgRWZmZWN0aXZlT3JnYW5pemF0aW9uOiAnd2F6dWgudGVzdHl0ZXN0LmNvbScsXG4gICAgTm9uUElJUGFyYW1ldGVyczogJy1FeHBvcnQgXCI8U05JUC1QSUk+XCInLFxuICAgIFBhcmFtZXRlcnM6ICctRXhwb3J0IFwiVHJ1ZVwiJyxcbiAgICBTdGFydFRpbWU6ICcyMDIxLTA1LTE4VDE3OjUwOjE1JyxcbiAgICBVc2VyU2VydmljZVBsYW46ICcnLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0xOFQxNzo1MDoxMicsXG4gICAgSWQ6ICc0NjkyMjAxZi04MTAxLTQ1NWUtYjg5ZC02NzI3ZWY3NWMyMjMnLFxuICAgIE9wZXJhdGlvbjogJ0dldC1Db21wbGlhbmNlVGFnJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogMTgsXG4gICAgUmVzdWx0U3RhdHVzOiAnU3VjY2VzcycsXG4gICAgVXNlcktleTogJ2Zha2VAZW1haWwubm90JyxcbiAgICBVc2VyVHlwZTogMixcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyJyxcbiAgICBPYmplY3RJZDogJycsXG4gICAgVXNlcklkOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIFNlY3VyaXR5Q29tcGxpYW5jZUNlbnRlckV2ZW50VHlwZTogMCxcbiAgICBDbGllbnRBcHBsaWNhdGlvbjogJ0VNQycsXG4gICAgQ21kbGV0VmVyc2lvbjogJy4uLicsXG4gICAgRWZmZWN0aXZlT3JnYW5pemF0aW9uOiAnd2F6dWgudGVzdHl0ZXN0LmNvbScsXG4gICAgTm9uUElJUGFyYW1ldGVyczogJy1JbmNsdWRpbmdMYWJlbFN0YXRlIFwiPFNOSVAtUElJPlwiJyxcbiAgICBQYXJhbWV0ZXJzOiAnLUluY2x1ZGluZ0xhYmVsU3RhdGUgXCJUcnVlXCInLFxuICAgIFN0YXJ0VGltZTogJzIwMjEtMDUtMThUMTc6NTA6MTInLFxuICAgIFVzZXJTZXJ2aWNlUGxhbjogJycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTE4VDE3OjUwOjEyJyxcbiAgICBJZDogJzdkNDFmMWYyLTU4N2MtNDkyZi1iNmZmLTJmOWQxYTUxOWM2MCcsXG4gICAgT3BlcmF0aW9uOiAnR2V0LUNvbXBsaWFuY2VTZWFyY2gnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiAxOCxcbiAgICBSZXN1bHRTdGF0dXM6ICdTdWNjZXNzJyxcbiAgICBVc2VyS2V5OiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIFVzZXJUeXBlOiAyLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTZWN1cml0eUNvbXBsaWFuY2VDZW50ZXInLFxuICAgIE9iamVjdElkOiAnJyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgU2VjdXJpdHlDb21wbGlhbmNlQ2VudGVyRXZlbnRUeXBlOiAwLFxuICAgIENsaWVudEFwcGxpY2F0aW9uOiAnRU1DJyxcbiAgICBDbWRsZXRWZXJzaW9uOiAnLi4uJyxcbiAgICBFZmZlY3RpdmVPcmdhbml6YXRpb246ICd3YXp1aC50ZXN0eXRlc3QuY29tJyxcbiAgICBOb25QSUlQYXJhbWV0ZXJzOiAnLVJlc3VsdFNpemUgXCJVbmxpbWl0ZWRcIicsXG4gICAgUGFyYW1ldGVyczogJy1SZXN1bHRTaXplIFwiVW5saW1pdGVkXCInLFxuICAgIFN0YXJ0VGltZTogJzIwMjEtMDUtMThUMTc6NTA6MTInLFxuICAgIFVzZXJTZXJ2aWNlUGxhbjogJycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTE4VDE3OjU5OjQ1JyxcbiAgICBJZDogJ2ViY2ZjMmJmLTg3OTktNDEzYy1hZGQ0LTZjMmI1M2NiNjhlNycsXG4gICAgT3BlcmF0aW9uOiAnR2V0LURscFNlbnNpdGl2ZUluZm9ybWF0aW9uVHlwZScsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDE4LFxuICAgIFJlc3VsdFN0YXR1czogJ1N1Y2Nlc3MnLFxuICAgIFVzZXJLZXk6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgVXNlclR5cGU6IDAsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ1NlY3VyaXR5Q29tcGxpYW5jZUNlbnRlcicsXG4gICAgT2JqZWN0SWQ6ICcnLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBTZWN1cml0eUNvbXBsaWFuY2VDZW50ZXJFdmVudFR5cGU6IDAsXG4gICAgQ2xpZW50QXBwbGljYXRpb246ICcnLFxuICAgIENtZGxldFZlcnNpb246ICcuLi4nLFxuICAgIEVmZmVjdGl2ZU9yZ2FuaXphdGlvbjogJ3dhenVoLnRlc3R5dGVzdC5jb20nLFxuICAgIE5vblBJSVBhcmFtZXRlcnM6ICctT3JnYW5pemF0aW9uIFwiMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViXCInLFxuICAgIFBhcmFtZXRlcnM6ICctT3JnYW5pemF0aW9uIFwiMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViXCInLFxuICAgIFN0YXJ0VGltZTogJzIwMjEtMDUtMThUMTc6NTk6NDUnLFxuICAgIFVzZXJTZXJ2aWNlUGxhbjogJycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTE4VDE0OjExOjQxJyxcbiAgICBJZDogJzdhZWNhMjI2LWIzZTctNDAzMy05YTdmLWQwNjc2MjJlOGQwMCcsXG4gICAgT3BlcmF0aW9uOiAnVXNlckxvZ2dlZEluJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogMTUsXG4gICAgUmVzdWx0U3RhdHVzOiAnU3VjY2VzcycsXG4gICAgVXNlcktleTogJzkxMGVkNWNhLTRlY2YtNDE0Yy1hMWJlLWQ1MzUxMWJmZTFhNScsXG4gICAgVXNlclR5cGU6IDAsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ0F6dXJlQWN0aXZlRGlyZWN0b3J5JyxcbiAgICBDbGllbnRJUDogJzE5MC4xNi45LjE3NicsXG4gICAgT2JqZWN0SWQ6ICc1ZjA5MzMzYS04NDJjLTQ3ZGEtYTE1Ny01N2RhMjdmY2JjYTUnLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBBenVyZUFjdGl2ZURpcmVjdG9yeUV2ZW50VHlwZTogMSxcbiAgICBFeHRlbmRlZFByb3BlcnRpZXM6IFtcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ1Jlc3VsdFN0YXR1c0RldGFpbCcsXG4gICAgICAgIFZhbHVlOiAnUmVkaXJlY3QnLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ1VzZXJBZ2VudCcsXG4gICAgICAgIFZhbHVlOlxuICAgICAgICAgICdNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvOTAuMC40NDMwLjIxMiBTYWZhcmkvNTM3LjM2JyxcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdSZXF1ZXN0VHlwZScsXG4gICAgICAgIFZhbHVlOiAnT0F1dGgyOkF1dGhvcml6ZScsXG4gICAgICB9LFxuICAgIF0sXG4gICAgTW9kaWZpZWRQcm9wZXJ0aWVzOiBbXSxcbiAgICBBY3RvcjogW1xuICAgICAge1xuICAgICAgICBJRDogJzkxMGVkNWNhLTRlY2YtNDE0Yy1hMWJlLWQ1MzUxMWJmZTFhNScsXG4gICAgICAgIFR5cGU6IDAsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBJRDogJ2Zha2VAZW1haWwubm90JyxcbiAgICAgICAgVHlwZTogNSxcbiAgICAgIH0sXG4gICAgXSxcbiAgICBBY3RvckNvbnRleHRJZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgQWN0b3JJcEFkZHJlc3M6ICcxOTAuMTYuOS4xNzYnLFxuICAgIEludGVyU3lzdGVtc0lkOiAnYTM3OTg3OTItZmVmMS00YjUzLWJkNDQtYmJiZDk0Y2YwZTVjJyxcbiAgICBJbnRyYVN5c3RlbUlkOiAnN2FlY2EyMjYtYjNlNy00MDMzLTlhN2YtZDA2NzYyMmU4ZDAwJyxcbiAgICBTdXBwb3J0VGlja2V0SWQ6ICcnLFxuICAgIFRhcmdldDogW1xuICAgICAge1xuICAgICAgICBJRDogJzVmMDkzMzNhLTg0MmMtNDdkYS1hMTU3LTU3ZGEyN2ZjYmNhNScsXG4gICAgICAgIFR5cGU6IDAsXG4gICAgICB9LFxuICAgIF0sXG4gICAgVGFyZ2V0Q29udGV4dElkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBBcHBsaWNhdGlvbklkOiAnODliZWUxZjctNWU2ZS00ZDhhLTlmM2QtZWNkNjAxMjU5ZGE3JyxcbiAgICBEZXZpY2VQcm9wZXJ0aWVzOiBbXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdPUycsXG4gICAgICAgIFZhbHVlOiAnV2luZG93cyAxMCcsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnQnJvd3NlclR5cGUnLFxuICAgICAgICBWYWx1ZTogJ0Nocm9tZScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnSXNDb21wbGlhbnRBbmRNYW5hZ2VkJyxcbiAgICAgICAgVmFsdWU6ICdGYWxzZScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnU2Vzc2lvbklkJyxcbiAgICAgICAgVmFsdWU6ICc3MTRjNDkzNS1hMjJkLTQwMGQtODU2My1mYmJkOGJmYzIzMDEnLFxuICAgICAgfSxcbiAgICBdLFxuICAgIEVycm9yTnVtYmVyOiAnMCcsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTE4VDE3OjQ5OjExJyxcbiAgICBJZDogJzRlNjIxNTYzLTM5NGYtNDJhOS04YThhLTg1NDllMWZmYTc3MScsXG4gICAgT3BlcmF0aW9uOiAnQWRkIHNlcnZpY2UgcHJpbmNpcGFsLicsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDgsXG4gICAgUmVzdWx0U3RhdHVzOiAnU3VjY2VzcycsXG4gICAgVXNlcktleTogJ05vdCBBdmFpbGFibGUnLFxuICAgIFVzZXJUeXBlOiA0LFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdBenVyZUFjdGl2ZURpcmVjdG9yeScsXG4gICAgT2JqZWN0SWQ6ICdmNzM4ZWYxNC00N2RjLTQ1NjQtYjUzYi00NTA2OTQ4NGNjYzcnLFxuICAgIFVzZXJJZDogJ1NlcnZpY2VQcmluY2lwYWxfNGJmODA3ODgtMGVjNC00ODFhLWFlN2ItYjcxNjQ3YmYzYjU3JyxcbiAgICBBenVyZUFjdGl2ZURpcmVjdG9yeUV2ZW50VHlwZTogMSxcbiAgICBFeHRlbmRlZFByb3BlcnRpZXM6IFtcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ2FkZGl0aW9uYWxEZXRhaWxzJyxcbiAgICAgICAgVmFsdWU6ICd7fScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnZXh0ZW5kZWRBdWRpdEV2ZW50Q2F0ZWdvcnknLFxuICAgICAgICBWYWx1ZTogJ1NlcnZpY2VQcmluY2lwYWwnLFxuICAgICAgfSxcbiAgICBdLFxuICAgIE1vZGlmaWVkUHJvcGVydGllczogW1xuICAgICAge1xuICAgICAgICBOYW1lOiAnQWNjb3VudEVuYWJsZWQnLFxuICAgICAgICBOZXdWYWx1ZTogJ1tcXHJcXG4gIHRydWVcXHJcXG5dJyxcbiAgICAgICAgT2xkVmFsdWU6ICdbXScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnQXBwUHJpbmNpcGFsSWQnLFxuICAgICAgICBOZXdWYWx1ZTogJ1tcXHJcXG4gIFwiZjczOGVmMTQtNDdkYy00NTY0LWI1M2ItNDUwNjk0ODRjY2M3XCJcXHJcXG5dJyxcbiAgICAgICAgT2xkVmFsdWU6ICdbXScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnRGlzcGxheU5hbWUnLFxuICAgICAgICBOZXdWYWx1ZTogJ1tcXHJcXG4gIFwiTWFya2V0cGxhY2UgQXBpXCJcXHJcXG5dJyxcbiAgICAgICAgT2xkVmFsdWU6ICdbXScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnU2VydmljZVByaW5jaXBhbE5hbWUnLFxuICAgICAgICBOZXdWYWx1ZTogJ1tcXHJcXG4gIFwiZjczOGVmMTQtNDdkYy00NTY0LWI1M2ItNDUwNjk0ODRjY2M3XCJcXHJcXG5dJyxcbiAgICAgICAgT2xkVmFsdWU6ICdbXScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnQ3JlZGVudGlhbCcsXG4gICAgICAgIE5ld1ZhbHVlOlxuICAgICAgICAgICdbXFxyXFxuICB7XFxyXFxuICAgIFwiQ3JlZGVudGlhbFR5cGVcIjogMixcXHJcXG4gICAgXCJLZXlTdG9yZUlkXCI6IFwiMjkxMTU0ZjAtYTlmNS00NWJiLTg3YmUtOWM4ZWU1YjZkNjJjXCIsXFxyXFxuICAgIFwiS2V5R3JvdXBJZFwiOiBcIjFjNWFhMDRiLWRlYTUtNDI4NC05OTA4LTQ3ZWRkMWUxMmQxM1wiXFxyXFxuICB9XFxyXFxuXScsXG4gICAgICAgIE9sZFZhbHVlOiAnW10nLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ0luY2x1ZGVkIFVwZGF0ZWQgUHJvcGVydGllcycsXG4gICAgICAgIE5ld1ZhbHVlOiAnQWNjb3VudEVuYWJsZWQsIEFwcFByaW5jaXBhbElkLCBEaXNwbGF5TmFtZSwgU2VydmljZVByaW5jaXBhbE5hbWUsIENyZWRlbnRpYWwnLFxuICAgICAgICBPbGRWYWx1ZTogJycsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnVGFyZ2V0SWQuU2VydmljZVByaW5jaXBhbE5hbWVzJyxcbiAgICAgICAgTmV3VmFsdWU6ICdmNzM4ZWYxNC00N2RjLTQ1NjQtYjUzYi00NTA2OTQ4NGNjYzcnLFxuICAgICAgICBPbGRWYWx1ZTogJycsXG4gICAgICB9LFxuICAgIF0sXG4gICAgQWN0b3I6IFtcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdXaW5kb3dzIEF6dXJlIFNlcnZpY2UgTWFuYWdlbWVudCBBUEknLFxuICAgICAgICBUeXBlOiAxLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICc3OTdmNDg0Ni1iYTAwLTRmZDctYmE0My1kYWMxZjhmNjMwMTMnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdTZXJ2aWNlUHJpbmNpcGFsXzRiZjgwNzg4LTBlYzQtNDgxYS1hZTdiLWI3MTY0N2JmM2I1NycsXG4gICAgICAgIFR5cGU6IDIsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBJRDogJzRiZjgwNzg4LTBlYzQtNDgxYS1hZTdiLWI3MTY0N2JmM2I1NycsXG4gICAgICAgIFR5cGU6IDIsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBJRDogJ1NlcnZpY2VQcmluY2lwYWwnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICBdLFxuICAgIEFjdG9yQ29udGV4dElkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBJbnRlclN5c3RlbXNJZDogJzljZmJhM2JiLWI0NzgtNDRhYS1hMTQwLTQ2NWVlN2YyOTI3NCcsXG4gICAgSW50cmFTeXN0ZW1JZDogJzIxMDUxODA1LTI0MTMtNTk0YS1hYjVkLTAwNjAxNDAwNTM0OCcsXG4gICAgU3VwcG9ydFRpY2tldElkOiAnJyxcbiAgICBUYXJnZXQ6IFtcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdTZXJ2aWNlUHJpbmNpcGFsX2Y2ZDJlYWJjLWQwMjAtNDY0My04MGE4LTJiOTJiMTYzZDFkZScsXG4gICAgICAgIFR5cGU6IDIsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBJRDogJ2Y2ZDJlYWJjLWQwMjAtNDY0My04MGE4LTJiOTJiMTYzZDFkZScsXG4gICAgICAgIFR5cGU6IDIsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBJRDogJ1NlcnZpY2VQcmluY2lwYWwnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdNYXJrZXRwbGFjZSBBcGknLFxuICAgICAgICBUeXBlOiAxLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdmNzM4ZWYxNC00N2RjLTQ1NjQtYjUzYi00NTA2OTQ4NGNjYzcnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdmNzM4ZWYxNC00N2RjLTQ1NjQtYjUzYi00NTA2OTQ4NGNjYzcnLFxuICAgICAgICBUeXBlOiA0LFxuICAgICAgfSxcbiAgICBdLFxuICAgIFRhcmdldENvbnRleHRJZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTE4VDIxOjQyOjI1JyxcbiAgICBJZDogJ2FmNGU1NTJmLTBiY2EtNGIwMi05MmM5LTRiZDQzMGYyNGY3NScsXG4gICAgT3BlcmF0aW9uOiAnQ2hhbmdlIHVzZXIgbGljZW5zZS4nLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiA4LFxuICAgIFJlc3VsdFN0YXR1czogJ1N1Y2Nlc3MnLFxuICAgIFVzZXJLZXk6ICcxMDAzMjAwMTQwODBEM0FEQHdhenVoLmNvbScsXG4gICAgVXNlclR5cGU6IDAsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ0F6dXJlQWN0aXZlRGlyZWN0b3J5JyxcbiAgICBPYmplY3RJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgQXp1cmVBY3RpdmVEaXJlY3RvcnlFdmVudFR5cGU6IDEsXG4gICAgRXh0ZW5kZWRQcm9wZXJ0aWVzOiBbXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdhZGRpdGlvbmFsRGV0YWlscycsXG4gICAgICAgIFZhbHVlOiAne30nLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ2V4dGVuZGVkQXVkaXRFdmVudENhdGVnb3J5JyxcbiAgICAgICAgVmFsdWU6ICdVc2VyJyxcbiAgICAgIH0sXG4gICAgXSxcbiAgICBNb2RpZmllZFByb3BlcnRpZXM6IFtdLFxuICAgIEFjdG9yOiBbXG4gICAgICB7XG4gICAgICAgIElEOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgICAgICBUeXBlOiA1LFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICcxMDAzMjAwMTQwODBEM0FEJyxcbiAgICAgICAgVHlwZTogMyxcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIElEOiAnVXNlcl85MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICc5MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdVc2VyJyxcbiAgICAgICAgVHlwZTogMixcbiAgICAgIH0sXG4gICAgXSxcbiAgICBBY3RvckNvbnRleHRJZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgSW50ZXJTeXN0ZW1zSWQ6ICcxZmQwOWQ2Yi01NGQzLTRhNTgtYWNmZS03MWNjMmM0MjlkOTcnLFxuICAgIEludHJhU3lzdGVtSWQ6ICcwYThhZTIwMS1lNDA0LTRmNmYtOTlkYi1hM2M5MmE1YmQwMjInLFxuICAgIFN1cHBvcnRUaWNrZXRJZDogJycsXG4gICAgVGFyZ2V0OiBbXG4gICAgICB7XG4gICAgICAgIElEOiAnVXNlcl85MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICc5MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdVc2VyJyxcbiAgICAgICAgVHlwZTogMixcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIElEOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgICAgICBUeXBlOiA1LFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICcxMDAzMjAwMTQwODBEM0FEJyxcbiAgICAgICAgVHlwZTogMyxcbiAgICAgIH0sXG4gICAgXSxcbiAgICBUYXJnZXRDb250ZXh0SWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0xOFQyMTo0MjoyNScsXG4gICAgSWQ6ICdiMjdlYWI4NC0xZWY3LTQzNzItYmM2OC03MjEzYWY4YWIzZmInLFxuICAgIE9wZXJhdGlvbjogJ1VwZGF0ZSB1c2VyLicsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDgsXG4gICAgUmVzdWx0U3RhdHVzOiAnU3VjY2VzcycsXG4gICAgVXNlcktleTogJzEwMDMyMDAxNDA4MEQzQURAd2F6dWguY29tJyxcbiAgICBVc2VyVHlwZTogMCxcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnQXp1cmVBY3RpdmVEaXJlY3RvcnknLFxuICAgIE9iamVjdElkOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBBenVyZUFjdGl2ZURpcmVjdG9yeUV2ZW50VHlwZTogMSxcbiAgICBFeHRlbmRlZFByb3BlcnRpZXM6IFtcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ2FkZGl0aW9uYWxEZXRhaWxzJyxcbiAgICAgICAgVmFsdWU6ICd7XCJVc2VyVHlwZVwiOlwiTWVtYmVyXCJ9JyxcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdleHRlbmRlZEF1ZGl0RXZlbnRDYXRlZ29yeScsXG4gICAgICAgIFZhbHVlOiAnVXNlcicsXG4gICAgICB9LFxuICAgIF0sXG4gICAgTW9kaWZpZWRQcm9wZXJ0aWVzOiBbXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdBc3NpZ25lZExpY2Vuc2UnLFxuICAgICAgICBOZXdWYWx1ZTpcbiAgICAgICAgICAnW1xcclxcbiAgXCJbU2t1TmFtZT1QT1dFUl9CSV9TVEFOREFSRCwgQWNjb3VudElkPTBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YiwgU2t1SWQ9YTQwM2ViY2MtZmFlMC00Y2EyLThjOGMtN2E5MDdmZDZjMjM1LCBEaXNhYmxlZFBsYW5zPVtdXVwiXFxyXFxuXScsXG4gICAgICAgIE9sZFZhbHVlOiAnW10nLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ0Fzc2lnbmVkUGxhbicsXG4gICAgICAgIE5ld1ZhbHVlOlxuICAgICAgICAgICdbXFxyXFxuICB7XFxyXFxuICAgIFwiU3Vic2NyaWJlZFBsYW5JZFwiOiBcImM5NzZkMDdmLWZkMGYtNDllYi1iZGMyLTI2YzE3NDgxZTFjNVwiLFxcclxcbiAgICBcIlNlcnZpY2VJbnN0YW5jZVwiOiBcIkF6dXJlQW5hbHlzaXMvU0RGXCIsXFxyXFxuICAgIFwiQ2FwYWJpbGl0eVN0YXR1c1wiOiAwLFxcclxcbiAgICBcIkFzc2lnbmVkVGltZXN0YW1wXCI6IFwiMjAyMS0wNS0xOFQyMTo0MjoyNS4zODk0MTY0WlwiLFxcclxcbiAgICBcIkluaXRpYWxTdGF0ZVwiOiBudWxsLFxcclxcbiAgICBcIkNhcGFiaWxpdHlcIjogbnVsbCxcXHJcXG4gICAgXCJTZXJ2aWNlUGxhbklkXCI6IFwiMjA0OWU1MjUtYjg1OS00MDFiLWIyYTAtZTBhMzFjNGIxZmU0XCJcXHJcXG4gIH1cXHJcXG5dJyxcbiAgICAgICAgT2xkVmFsdWU6ICdbXScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnSW5jbHVkZWQgVXBkYXRlZCBQcm9wZXJ0aWVzJyxcbiAgICAgICAgTmV3VmFsdWU6ICdBc3NpZ25lZExpY2Vuc2UsIEFzc2lnbmVkUGxhbicsXG4gICAgICAgIE9sZFZhbHVlOiAnJyxcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdUYXJnZXRJZC5Vc2VyVHlwZScsXG4gICAgICAgIE5ld1ZhbHVlOiAnTWVtYmVyJyxcbiAgICAgICAgT2xkVmFsdWU6ICcnLFxuICAgICAgfSxcbiAgICBdLFxuICAgIEFjdG9yOiBbXG4gICAgICB7XG4gICAgICAgIElEOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgICAgICBUeXBlOiA1LFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICcxMDAzMjAwMTQwODBEM0FEJyxcbiAgICAgICAgVHlwZTogMyxcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIElEOiAnVXNlcl85MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICc5MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdVc2VyJyxcbiAgICAgICAgVHlwZTogMixcbiAgICAgIH0sXG4gICAgXSxcbiAgICBBY3RvckNvbnRleHRJZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgSW50ZXJTeXN0ZW1zSWQ6ICcxZmQwOWQ2Yi01NGQzLTRhNTgtYWNmZS03MWNjMmM0MjlkOTcnLFxuICAgIEludHJhU3lzdGVtSWQ6ICcwYThhZTIwMS1lNDA0LTRmNmYtOTlkYi1hM2M5MmE1YmQwMjInLFxuICAgIFN1cHBvcnRUaWNrZXRJZDogJycsXG4gICAgVGFyZ2V0OiBbXG4gICAgICB7XG4gICAgICAgIElEOiAnVXNlcl85MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICc5MTBlZDVjYS00ZWNmLTQxNGMtYTFiZS1kNTM1MTFiZmUxYTUnLFxuICAgICAgICBUeXBlOiAyLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICdVc2VyJyxcbiAgICAgICAgVHlwZTogMixcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIElEOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgICAgICBUeXBlOiA1LFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgSUQ6ICcxMDAzMjAwMTQwODBEM0FEJyxcbiAgICAgICAgVHlwZTogMyxcbiAgICAgIH0sXG4gICAgXSxcbiAgICBUYXJnZXRDb250ZXh0SWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0yMFQxNzo0MzowMCcsXG4gICAgSWQ6ICc4YzNkMDIxNS02NmYwLTQxYjAtMzIwNS0wOGQ5MWJiNmI2M2MnLFxuICAgIE9wZXJhdGlvbjogJ1NoYXJpbmdQb2xpY3lDaGFuZ2VkJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogNCxcbiAgICBVc2VyS2V5OiAnaTowaC5mfG1lbWJlcnNoaXB8MTAwMzIwMDE0MDgwZDNhZEBsaXZlLmNvbScsXG4gICAgVXNlclR5cGU6IDAsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ09uZURyaXZlJyxcbiAgICBDbGllbnRJUDogJzIwLjE5MC4xNTcuMjcnLFxuICAgIE9iamVjdElkOiAnaHR0cHM6Ly93YXp1aC1teS5zaGFyZXBvaW50LmNvbS9wZXJzb25hbC90b21hc190dXJpbmFfd2F6dWhfY29tJyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgQ29ycmVsYXRpb25JZDogJ2ZkOWFjNzlkLTExMDAtNDhhYS05MmM1LTQwYTczYTFkNDQzZicsXG4gICAgRXZlbnRTb3VyY2U6ICdTaGFyZVBvaW50JyxcbiAgICBJdGVtVHlwZTogJ1NpdGUnLFxuICAgIFNpdGU6ICdmNDlmZWFlNC0wMzNkLTQwMjgtOTdkMS0zYWNkNTUzNDFmNjknLFxuICAgIFVzZXJBZ2VudDpcbiAgICAgICdNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvOTAuMC40NDMwLjIxMiBTYWZhcmkvNTM3LjM2JyxcbiAgICBNb2RpZmllZFByb3BlcnRpZXM6IFtcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ1NoYXJlVXNpbmdBbm9ueW1vdXNMaW5rcycsXG4gICAgICAgIE5ld1ZhbHVlOiAnRW5hYmxlZCcsXG4gICAgICAgIE9sZFZhbHVlOiAnRGlzYWJsZWQnLFxuICAgICAgfSxcbiAgICBdLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0yMFQxNzo0MzowMCcsXG4gICAgSWQ6ICczNWExYjUxNS0yYTBlLTRiZDYtZDBhMy0wOGQ5MWJiNmI2MzknLFxuICAgIE9wZXJhdGlvbjogJ1NpdGVDb2xsZWN0aW9uQ3JlYXRlZCcsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDQsXG4gICAgVXNlcktleTogJ2k6MGguZnxtZW1iZXJzaGlwfDEwMDMyMDAxNDA4MGQzYWRAbGl2ZS5jb20nLFxuICAgIFVzZXJUeXBlOiAwLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdPbmVEcml2ZScsXG4gICAgQ2xpZW50SVA6ICcyMC4xOTAuMTU3LjI3JyxcbiAgICBPYmplY3RJZDogJ2h0dHBzOi8vd2F6dWgtbXkuc2hhcmVwb2ludC5jb20vcGVyc29uYWwvdG9tYXNfdHVyaW5hX3dhenVoX2NvbScsXG4gICAgVXNlcklkOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIENvcnJlbGF0aW9uSWQ6ICdmZDlhYzc5ZC0xMTAwLTQ4YWEtOTJjNS00MGE3M2ExZDQ0M2YnLFxuICAgIEV2ZW50U291cmNlOiAnU2hhcmVQb2ludCcsXG4gICAgSXRlbVR5cGU6ICdTaXRlJyxcbiAgICBTaXRlOiAnZjQ5ZmVhZTQtMDMzZC00MDI4LTk3ZDEtM2FjZDU1MzQxZjY5JyxcbiAgICBVc2VyQWdlbnQ6XG4gICAgICAnTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkwLjAuNDQzMC4yMTIgU2FmYXJpLzUzNy4zNicsXG4gICAgRXZlbnREYXRhOlxuICAgICAgJzxTaXRlQ3JlYXRpb25Tb3VyY2U+QVBJPC9TaXRlQ3JlYXRpb25Tb3VyY2U+PFRlbmFudFNldHRpbmdzLlNob3dDcmVhdGVTaXRlQ29tbWFuZD5UcnVlPC9UZW5hbnRTZXR0aW5ncy5TaG93Q3JlYXRlU2l0ZUNvbW1hbmQ+PFRlbmFudFNldHRpbmdzLlVzZUN1c3RvbVNpdGVDcmVhdGlvbkZvcm0+RmFsc2U8L1RlbmFudFNldHRpbmdzLlVzZUN1c3RvbVNpdGVDcmVhdGlvbkZvcm0+JyxcbiAgfSxcbiAge1xuICAgIENyZWF0aW9uVGltZTogJzIwMjEtMDUtMjBUMTc6NDM6MDAnLFxuICAgIElkOiAnMzQ0ZjkxMzktZjQzNy00MjkwLTk1NjYtMDhkOTFiYjZiNjFmJyxcbiAgICBPcGVyYXRpb246ICdTaXRlQ29sbGVjdGlvbkFkbWluUmVtb3ZlZCcsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDE0LFxuICAgIFVzZXJLZXk6ICdpOjBoLmZ8bWVtYmVyc2hpcHwxMDAzMjAwMTQwODBkM2FkQGxpdmUuY29tJyxcbiAgICBVc2VyVHlwZTogMCxcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnT25lRHJpdmUnLFxuICAgIENsaWVudElQOiAnMjAuMTkwLjE1Ny4yNycsXG4gICAgT2JqZWN0SWQ6ICdodHRwczovL3dhenVoLW15LnNoYXJlcG9pbnQuY29tL3BlcnNvbmFsL3RvbWFzX3R1cmluYV93YXp1aF9jb20nLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBDb3JyZWxhdGlvbklkOiAnZmQ5YWM3OWQtMTEwMC00OGFhLTkyYzUtNDBhNzNhMWQ0NDNmJyxcbiAgICBFdmVudFNvdXJjZTogJ1NoYXJlUG9pbnQnLFxuICAgIEl0ZW1UeXBlOiAnV2ViJyxcbiAgICBTaXRlOiAnZjQ5ZmVhZTQtMDMzZC00MDI4LTk3ZDEtM2FjZDU1MzQxZjY5JyxcbiAgICBVc2VyQWdlbnQ6XG4gICAgICAnTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkwLjAuNDQzMC4yMTIgU2FmYXJpLzUzNy4zNicsXG4gICAgV2ViSWQ6ICdhOWQxNWIyMy02YWM5LTQzYzUtYWYzYy1iNGEwOTE2NjMxYzEnLFxuICAgIE1vZGlmaWVkUHJvcGVydGllczogW1xuICAgICAge1xuICAgICAgICBOYW1lOiAnU2l0ZUFkbWluJyxcbiAgICAgICAgTmV3VmFsdWU6ICcnLFxuICAgICAgICBPbGRWYWx1ZTogJycsXG4gICAgICB9LFxuICAgIF0sXG4gICAgVGFyZ2V0VXNlck9yR3JvdXBUeXBlOiAnTWVtYmVyJyxcbiAgICBTaXRlVXJsOiAnaHR0cHM6Ly93YXp1aC1teS5zaGFyZXBvaW50LmNvbS9wZXJzb25hbC90b21hc190dXJpbmFfd2F6dWhfY29tJyxcbiAgICBUYXJnZXRVc2VyT3JHcm91cE5hbWU6ICdTSEFSRVBPSU5UXFxcXHN5c3RlbScsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTIwVDE3OjQzOjAwJyxcbiAgICBJZDogJ2QzNmU0YjRkLTFlOGItNDYzNC02ZGQ4LTA4ZDkxYmI2YjYxOCcsXG4gICAgT3BlcmF0aW9uOiAnU2l0ZUNvbGxlY3Rpb25BZG1pbkFkZGVkJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogMTQsXG4gICAgVXNlcktleTogJ2k6MGguZnxtZW1iZXJzaGlwfDEwMDMyMDAxNDA4MGQzYWRAbGl2ZS5jb20nLFxuICAgIFVzZXJUeXBlOiAwLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdPbmVEcml2ZScsXG4gICAgQ2xpZW50SVA6ICcyMC4xOTAuMTU3LjI3JyxcbiAgICBPYmplY3RJZDogJ2h0dHBzOi8vd2F6dWgtbXkuc2hhcmVwb2ludC5jb20vcGVyc29uYWwvdG9tYXNfdHVyaW5hX3dhenVoX2NvbScsXG4gICAgVXNlcklkOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIENvcnJlbGF0aW9uSWQ6ICdmZDlhYzc5ZC0xMTAwLTQ4YWEtOTJjNS00MGE3M2ExZDQ0M2YnLFxuICAgIEV2ZW50U291cmNlOiAnU2hhcmVQb2ludCcsXG4gICAgSXRlbVR5cGU6ICdXZWInLFxuICAgIFNpdGU6ICdmNDlmZWFlNC0wMzNkLTQwMjgtOTdkMS0zYWNkNTUzNDFmNjknLFxuICAgIFVzZXJBZ2VudDpcbiAgICAgICdNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvOTAuMC40NDMwLjIxMiBTYWZhcmkvNTM3LjM2JyxcbiAgICBXZWJJZDogJ2E5ZDE1YjIzLTZhYzktNDNjNS1hZjNjLWI0YTA5MTY2MzFjMScsXG4gICAgTW9kaWZpZWRQcm9wZXJ0aWVzOiBbXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdTaXRlQWRtaW4nLFxuICAgICAgICBOZXdWYWx1ZTogJ2Zha2VAZW1haWwubm90JyxcbiAgICAgICAgT2xkVmFsdWU6ICcnLFxuICAgICAgfSxcbiAgICBdLFxuICAgIFRhcmdldFVzZXJPckdyb3VwVHlwZTogJ01lbWJlcicsXG4gICAgU2l0ZVVybDogJ2h0dHBzOi8vd2F6dWgtbXkuc2hhcmVwb2ludC5jb20vcGVyc29uYWwvdG9tYXNfdHVyaW5hX3dhenVoX2NvbScsXG4gICAgVGFyZ2V0VXNlck9yR3JvdXBOYW1lOiAnZmFrZUBlbWFpbC5ub3QnLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0yMFQxNzo0MzoyMicsXG4gICAgSWQ6ICcwZDZhNjJkMy1lNGJkLTQ0ZWUtY2U4ZC0wOGQ5MWJiNmMzOTInLFxuICAgIE9wZXJhdGlvbjogJ1BhZ2VWaWV3ZWQnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiA0LFxuICAgIFVzZXJLZXk6ICdpOjBoLmZ8bWVtYmVyc2hpcHwxMDAzMjAwMTQwODBkM2FkQGxpdmUuY29tJyxcbiAgICBVc2VyVHlwZTogMCxcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnU2hhcmVQb2ludCcsXG4gICAgQ2xpZW50SVA6ICcxOTAuMTYuOS4xNzYnLFxuICAgIE9iamVjdElkOiAnaHR0cHM6Ly93YXp1aC5zaGFyZXBvaW50LmNvbS9fbGF5b3V0cy8xNS9DcmVhdGVHcm91cC5hc3B4JyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgQ29ycmVsYXRpb25JZDogJ2NjZDBjOTlmLTMwOWItMjAwMC1kZjEzLTNmY2NhOWE4YzhlMScsXG4gICAgQ3VzdG9tVW5pcXVlSWQ6IHRydWUsXG4gICAgRXZlbnRTb3VyY2U6ICdTaGFyZVBvaW50JyxcbiAgICBJdGVtVHlwZTogJ1BhZ2UnLFxuICAgIExpc3RJdGVtVW5pcXVlSWQ6ICc1OWE4NDMzZC05YmI4LWNmZWYtNjViNy1lZjM1ZGUwMGM4ZjYnLFxuICAgIFNpdGU6ICdmN2ZiYjgwNS01ZjZiLTQ5NTAtYjY4MS0yMzY1ZWI0NjA4MWYnLFxuICAgIFVzZXJBZ2VudDpcbiAgICAgICdNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvOTAuMC40NDMwLjIxMiBTYWZhcmkvNTM3LjM2JyxcbiAgICBXZWJJZDogJzNiNTZkYjQ5LTYwZTMtNDEwZS1hY2JkLWQ4NzY1NDY3Mzg4YScsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTIwVDE3OjQ1OjU3JyxcbiAgICBJZDogJzE4YmIzNTFiLTQ5ZTEtNDdkZi04ZjRkLTA4ZDkxYmI3MWZmZCcsXG4gICAgT3BlcmF0aW9uOiAnQWRkZWRUb0dyb3VwJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogMTQsXG4gICAgVXNlcktleTogJ2k6MGguZnxtZW1iZXJzaGlwfDEwMDMyMDAxNDA4MGQzYWRAbGl2ZS5jb20nLFxuICAgIFVzZXJUeXBlOiAwLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTaGFyZVBvaW50JyxcbiAgICBDbGllbnRJUDogJzE5MC4xNi45LjE3NicsXG4gICAgT2JqZWN0SWQ6ICdodHRwczovL3dhenVoLnNoYXJlcG9pbnQuY29tL3NpdGVzL1Rlc3RTaGFyZVBvaW50JyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgQ29ycmVsYXRpb25JZDogJ2YxZDBjOTlmLTMwOTQtMjAwMC1kYTgyLTQ1NGYwMzRjYTYyOScsXG4gICAgRXZlbnRTb3VyY2U6ICdTaGFyZVBvaW50JyxcbiAgICBJdGVtVHlwZTogJ1dlYicsXG4gICAgU2l0ZTogJ2RkNThlZjA4LWZhZWEtNGNiNS04NDdhLTM1YmI1YzAxZTc1NycsXG4gICAgVXNlckFnZW50OlxuICAgICAgJ01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS85MC4wLjQ0MzAuMjEyIFNhZmFyaS81MzcuMzYnLFxuICAgIFdlYklkOiAnMDBjMzI1NTUtZTBkOC00MjVmLTlmYmQtZWY1NTM5YmZlY2Y3JyxcbiAgICBFdmVudERhdGE6ICc8R3JvdXA+U2l0ZSBPd25lcnM8L0dyb3VwPicsXG4gICAgVGFyZ2V0VXNlck9yR3JvdXBUeXBlOiAnTWVtYmVyJyxcbiAgICBTaXRlVXJsOiAnaHR0cHM6Ly93YXp1aC5zaGFyZXBvaW50LmNvbS9zaXRlcy9UZXN0U2hhcmVQb2ludCcsXG4gICAgVGFyZ2V0VXNlck9yR3JvdXBOYW1lOiAnU0hBUkVQT0lOVFxcXFxzeXN0ZW0nLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0yMFQxNzo0NjoyNicsXG4gICAgSWQ6ICcyOWJkZTg0YS1kM2VjLTQzODgtNDYwMC0wOGQ5MWJiNzMwYmMnLFxuICAgIE9wZXJhdGlvbjogJ0ZpbGVBY2Nlc3NlZCcsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDYsXG4gICAgVXNlcktleTogJ2k6MGguZnxtZW1iZXJzaGlwfDEwMDMyMDAxNDA4MGQzYWRAbGl2ZS5jb20nLFxuICAgIFVzZXJUeXBlOiAwLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTaGFyZVBvaW50JyxcbiAgICBDbGllbnRJUDogJzE5MC4xNi45LjE3NicsXG4gICAgT2JqZWN0SWQ6XG4gICAgICAnaHR0cHM6Ly93YXp1aC5zaGFyZXBvaW50LmNvbS9zaXRlcy9UZXN0U2hhcmVQb2ludC9TaGFyZWQgRG9jdW1lbnRzL0Zvcm1zL0FsbEl0ZW1zLmFzcHgnLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBDb3JyZWxhdGlvbklkOiAnZjlkMGM5OWYtYjA0Zi0yMDAwLWRhODItNGJiMmFiZjYxNjhmJyxcbiAgICBFdmVudFNvdXJjZTogJ1NoYXJlUG9pbnQnLFxuICAgIEl0ZW1UeXBlOiAnRmlsZScsXG4gICAgTGlzdElkOiAnZmQyZWJhZjAtOTAwYi00ZGZmLThmYzItZDM0OGJlNTFlNjc3JyxcbiAgICBMaXN0SXRlbVVuaXF1ZUlkOiAnM2M5ZDg5NDMtODQ2ZS00MWYzLWE2NDctNzJhNWU0ZTNkZWNmJyxcbiAgICBTaXRlOiAnZGQ1OGVmMDgtZmFlYS00Y2I1LTg0N2EtMzViYjVjMDFlNzU3JyxcbiAgICBVc2VyQWdlbnQ6XG4gICAgICAnTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkwLjAuNDQzMC4yMTIgU2FmYXJpLzUzNy4zNicsXG4gICAgV2ViSWQ6ICcwMGMzMjU1NS1lMGQ4LTQyNWYtOWZiZC1lZjU1MzliZmVjZjcnLFxuICAgIFNvdXJjZUZpbGVFeHRlbnNpb246ICdhc3B4JyxcbiAgICBTaXRlVXJsOiAnaHR0cHM6Ly93YXp1aC5zaGFyZXBvaW50LmNvbS9zaXRlcy9UZXN0U2hhcmVQb2ludC8nLFxuICAgIFNvdXJjZUZpbGVOYW1lOiAnQWxsSXRlbXMuYXNweCcsXG4gICAgU291cmNlUmVsYXRpdmVVcmw6ICdTaGFyZWQgRG9jdW1lbnRzL0Zvcm1zJyxcbiAgfSxcbiAge1xuICAgIENyZWF0aW9uVGltZTogJzIwMjEtMDUtMjBUMTc6NDY6MjUnLFxuICAgIElkOiAnMDg3ZTViNjgtZmMzZi00ZTAxLTFlZmMtMDhkOTFiYjczMGI1JyxcbiAgICBPcGVyYXRpb246ICdMaXN0Vmlld2VkJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogMzYsXG4gICAgVXNlcktleTogJ2k6MGguZnxtZW1iZXJzaGlwfDEwMDMyMDAxNDA4MGQzYWRAbGl2ZS5jb20nLFxuICAgIFVzZXJUeXBlOiAwLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTaGFyZVBvaW50JyxcbiAgICBDbGllbnRJUDogJzE5MC4xNi45LjE3NicsXG4gICAgT2JqZWN0SWQ6XG4gICAgICAnaHR0cHM6Ly93YXp1aC5zaGFyZXBvaW50LmNvbS9zaXRlcy9UZXN0U2hhcmVQb2ludC9mZDJlYmFmMC05MDBiLTRkZmYtOGZjMi1kMzQ4YmU1MWU2NzcnLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBDb3JyZWxhdGlvbklkOiAnZjlkMGM5OWYtYjA0Zi0yMDAwLWRhODItNGJiMmFiZjYxNjhmJyxcbiAgICBEb05vdERpc3RyaWJ1dGVFdmVudDogdHJ1ZSxcbiAgICBFdmVudFNvdXJjZTogJ1NoYXJlUG9pbnQnLFxuICAgIEl0ZW1UeXBlOiAnTGlzdCcsXG4gICAgTGlzdElkOiAnZmQyZWJhZjAtOTAwYi00ZGZmLThmYzItZDM0OGJlNTFlNjc3JyxcbiAgICBTaXRlOiAnZGQ1OGVmMDgtZmFlYS00Y2I1LTg0N2EtMzViYjVjMDFlNzU3JyxcbiAgICBVc2VyQWdlbnQ6XG4gICAgICAnTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkwLjAuNDQzMC4yMTIgU2FmYXJpLzUzNy4zNicsXG4gICAgV2ViSWQ6ICcwMGMzMjU1NS1lMGQ4LTQyNWYtOWZiZC1lZjU1MzliZmVjZjcnLFxuICAgIEN1c3RvbWl6ZWREb2NsaWI6IGZhbHNlLFxuICAgIEZyb21BcHA6IHRydWUsXG4gICAgSXNEb2NMaWI6IHRydWUsXG4gICAgSXRlbUNvdW50OiAwLFxuICAgIExpc3RCYXNlVGVtcGxhdGVUeXBlOiAnMTAxJyxcbiAgICBMaXN0QmFzZVR5cGU6ICdEb2N1bWVudExpYnJhcnknLFxuICAgIExpc3RDb2xvcjogJycsXG4gICAgTGlzdEljb246ICcnLFxuICAgIFNvdXJjZTogJ1Vua25vd24nLFxuICAgIFRlbXBsYXRlVHlwZUlkOiAnJyxcbiAgICBMaXN0VGl0bGU6ICdmZDJlYmFmMC05MDBiLTRkZmYtOGZjMi1kMzQ4YmU1MWU2NzcnLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0yMFQxNzo1MjoyOScsXG4gICAgSWQ6ICc0MTIyNTQ4Ny0zMWMxLTRlMjQtYjhiMC0wOGQ5MWJiODA5NGMnLFxuICAgIE9wZXJhdGlvbjogJ1BhZ2VQcmVmZXRjaGVkJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogNCxcbiAgICBVc2VyS2V5OiAnaTowaC5mfG1lbWJlcnNoaXB8MTAwMzIwMDE0MDgwZDNhZEBsaXZlLmNvbScsXG4gICAgVXNlclR5cGU6IDAsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ1NoYXJlUG9pbnQnLFxuICAgIENsaWVudElQOiAnMTkwLjE2LjkuMTc2JyxcbiAgICBPYmplY3RJZDogJ2h0dHBzOi8vd2F6dWguc2hhcmVwb2ludC5jb20vc2l0ZXMvVGVzdFNoYXJlUG9pbnQnLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBDb3JyZWxhdGlvbklkOiAnNTJkMWM5OWYtMzAwMC0yMDAwLWRmMTMtM2FiMWU4ZmI5ZjkyJyxcbiAgICBDdXN0b21VbmlxdWVJZDogZmFsc2UsXG4gICAgRXZlbnRTb3VyY2U6ICdTaGFyZVBvaW50JyxcbiAgICBJdGVtVHlwZTogJ1BhZ2UnLFxuICAgIExpc3RJZDogJ2U0YzljZTJlLWQ4YzItNDY4ZS1iYWY1LWYzNjJmOGMyZjJmMycsXG4gICAgTGlzdEl0ZW1VbmlxdWVJZDogJzM2ZGIzMTY4LWMxYjItNDRlOS05ZmZkLWU5YThlMDRiYjJmNScsXG4gICAgU2l0ZTogJ2RkNThlZjA4LWZhZWEtNGNiNS04NDdhLTM1YmI1YzAxZTc1NycsXG4gICAgVXNlckFnZW50OlxuICAgICAgJ01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS85MC4wLjQ0MzAuMjEyIFNhZmFyaS81MzcuMzYnLFxuICAgIFdlYklkOiAnMDBjMzI1NTUtZTBkOC00MjVmLTlmYmQtZWY1NTM5YmZlY2Y3JyxcbiAgfSxcbiAge1xuICAgIENyZWF0aW9uVGltZTogJzIwMjEtMDUtMjBUMTc6NTE6NDknLFxuICAgIElkOiAnZDkzMGNjNWMtMjY1OC00NWRmLTYzNjEtMDhkOTFiYjdmMTc5JyxcbiAgICBPcGVyYXRpb246ICdGaWxlQ2hlY2tlZE91dCcsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDYsXG4gICAgVXNlcktleTogJ2k6MGguZnxtZW1iZXJzaGlwfDEwMDMyMDAxNDA4MGQzYWRAbGl2ZS5jb20nLFxuICAgIFVzZXJUeXBlOiAwLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTaGFyZVBvaW50JyxcbiAgICBDbGllbnRJUDogJzE5MC4xNi45LjE3NicsXG4gICAgT2JqZWN0SWQ6ICdodHRwczovL3dhenVoLnNoYXJlcG9pbnQuY29tL3NpdGVzL1Rlc3RTaGFyZVBvaW50L1NpdGVQYWdlcy9Ib21lLmFzcHgnLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBDb3JyZWxhdGlvbklkOiAnNDhkMWM5OWYtZjAzYy0yMDAwLWRmMTMtMzg5ODNhNjYwOGY4JyxcbiAgICBFdmVudFNvdXJjZTogJ1NoYXJlUG9pbnQnLFxuICAgIEl0ZW1UeXBlOiAnRmlsZScsXG4gICAgTGlzdElkOiAnZTRjOWNlMmUtZDhjMi00NjhlLWJhZjUtZjM2MmY4YzJmMmYzJyxcbiAgICBMaXN0SXRlbVVuaXF1ZUlkOiAnMzZkYjMxNjgtYzFiMi00NGU5LTlmZmQtZTlhOGUwNGJiMmY1JyxcbiAgICBTaXRlOiAnZGQ1OGVmMDgtZmFlYS00Y2I1LTg0N2EtMzViYjVjMDFlNzU3JyxcbiAgICBVc2VyQWdlbnQ6XG4gICAgICAnTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkwLjAuNDQzMC4yMTIgU2FmYXJpLzUzNy4zNicsXG4gICAgV2ViSWQ6ICcwMGMzMjU1NS1lMGQ4LTQyNWYtOWZiZC1lZjU1MzliZmVjZjcnLFxuICAgIEhpZ2hQcmlvcml0eU1lZGlhUHJvY2Vzc2luZzogZmFsc2UsXG4gICAgU291cmNlRmlsZUV4dGVuc2lvbjogJ2FzcHgnLFxuICAgIFNpdGVVcmw6ICdodHRwczovL3dhenVoLnNoYXJlcG9pbnQuY29tL3NpdGVzL1Rlc3RTaGFyZVBvaW50LycsXG4gICAgU291cmNlRmlsZU5hbWU6ICdIb21lLmFzcHgnLFxuICAgIFNvdXJjZVJlbGF0aXZlVXJsOiAnU2l0ZVBhZ2VzJyxcbiAgfSxcbiAge1xuICAgIENyZWF0aW9uVGltZTogJzIwMjEtMDUtMjBUMTc6NTE6NTEnLFxuICAgIElkOiAnODlkNzYzNjItZTQ5My00YzIwLTNiNjktMDhkOTFiYjdmMjg4JyxcbiAgICBPcGVyYXRpb246ICdMaXN0VXBkYXRlZCcsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDM2LFxuICAgIFVzZXJLZXk6ICdpOjBoLmZ8bWVtYmVyc2hpcHwxMDAzMjAwMTQwODBkM2FkQGxpdmUuY29tJyxcbiAgICBVc2VyVHlwZTogMCxcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnU2hhcmVQb2ludCcsXG4gICAgQ2xpZW50SVA6ICcxOTAuMTYuOS4xNzYnLFxuICAgIE9iamVjdElkOlxuICAgICAgJ2h0dHBzOi8vd2F6dWguc2hhcmVwb2ludC5jb20vc2l0ZXMvVGVzdFNoYXJlUG9pbnQvZTRjOWNlMmUtZDhjMi00NjhlLWJhZjUtZjM2MmY4YzJmMmYzJyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgQ29ycmVsYXRpb25JZDogJzQ4ZDFjOTlmLWYwYTgtMjAwMC1kYTgyLTQxYmUzZjk3MzI2NycsXG4gICAgRG9Ob3REaXN0cmlidXRlRXZlbnQ6IHRydWUsXG4gICAgRXZlbnRTb3VyY2U6ICdTaGFyZVBvaW50JyxcbiAgICBJdGVtVHlwZTogJ0xpc3QnLFxuICAgIExpc3RJZDogJ2U0YzljZTJlLWQ4YzItNDY4ZS1iYWY1LWYzNjJmOGMyZjJmMycsXG4gICAgU2l0ZTogJ2RkNThlZjA4LWZhZWEtNGNiNS04NDdhLTM1YmI1YzAxZTc1NycsXG4gICAgVXNlckFnZW50OlxuICAgICAgJ01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS85MC4wLjQ0MzAuMjEyIFNhZmFyaS81MzcuMzYnLFxuICAgIFdlYklkOiAnMDBjMzI1NTUtZTBkOC00MjVmLTlmYmQtZWY1NTM5YmZlY2Y3JyxcbiAgICBDdXN0b21pemVkRG9jbGliOiBmYWxzZSxcbiAgICBGcm9tQXBwOiBmYWxzZSxcbiAgICBJc0RvY0xpYjogdHJ1ZSxcbiAgICBJdGVtQ291bnQ6IDEsXG4gICAgTGlzdEJhc2VUZW1wbGF0ZVR5cGU6ICcxMTknLFxuICAgIExpc3RCYXNlVHlwZTogJ0RvY3VtZW50TGlicmFyeScsXG4gICAgTGlzdENvbG9yOiAnJyxcbiAgICBMaXN0SWNvbjogJycsXG4gICAgU291cmNlOiAnVW5rbm93bicsXG4gICAgVGVtcGxhdGVUeXBlSWQ6ICcnLFxuICAgIExpc3RUaXRsZTogJ2U0YzljZTJlLWQ4YzItNDY4ZS1iYWY1LWYzNjJmOGMyZjJmMycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTIwVDE3OjUyOjM2JyxcbiAgICBJZDogJzdhOTFkZDhjLTU2MGItNGZiZS0yNTg1LTA4ZDkxYmI4MGQ0NicsXG4gICAgT3BlcmF0aW9uOiAnQ2xpZW50Vmlld1NpZ25hbGVkJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogNCxcbiAgICBVc2VyS2V5OiAnaTowaC5mfG1lbWJlcnNoaXB8MTAwMzIwMDE0MDgwZDNhZEBsaXZlLmNvbScsXG4gICAgVXNlclR5cGU6IDAsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ1NoYXJlUG9pbnQnLFxuICAgIENsaWVudElQOiAnMTkwLjE2LjkuMTc2JyxcbiAgICBPYmplY3RJZDogJ2h0dHBzOi8vd2F6dWguc2hhcmVwb2ludC5jb20vc2l0ZXMvVGVzdFNoYXJlUG9pbnQvU2l0ZVBhZ2VzL0hvbWUuYXNweCcsXG4gICAgVXNlcklkOiAnZmFrZUBlbWFpbC5ub3QnLFxuICAgIENvcnJlbGF0aW9uSWQ6ICc1M2QxYzk5Zi1iMGFhLTIwMDAtZGYxMy0zZWZlYTllNDEwNzEnLFxuICAgIEN1c3RvbVVuaXF1ZUlkOiBmYWxzZSxcbiAgICBFdmVudFNvdXJjZTogJ1NoYXJlUG9pbnQnLFxuICAgIEl0ZW1UeXBlOiAnUGFnZScsXG4gICAgTGlzdElkOiAnZTRjOWNlMmUtZDhjMi00NjhlLWJhZjUtZjM2MmY4YzJmMmYzJyxcbiAgICBMaXN0SXRlbVVuaXF1ZUlkOiAnMzZkYjMxNjgtYzFiMi00NGU5LTlmZmQtZTlhOGUwNGJiMmY1JyxcbiAgICBTaXRlOiAnZGQ1OGVmMDgtZmFlYS00Y2I1LTg0N2EtMzViYjVjMDFlNzU3JyxcbiAgICBVc2VyQWdlbnQ6XG4gICAgICAnTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkwLjAuNDQzMC4yMTIgU2FmYXJpLzUzNy4zNicsXG4gICAgV2ViSWQ6ICcwMGMzMjU1NS1lMGQ4LTQyNWYtOWZiZC1lZjU1MzliZmVjZjcnLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0yMFQxNzo1MzozNycsXG4gICAgSWQ6ICc5Njk1YWZjZC0xOWZmLTQ5MWYtYTZlZS0wOGQ5MWJiODMxZDEnLFxuICAgIE9wZXJhdGlvbjogJ0ZpbGVNb2RpZmllZCcsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDYsXG4gICAgVXNlcktleTogJ2k6MGguZnxtZW1iZXJzaGlwfDEwMDMyMDAxNDA4MGQzYWRAbGl2ZS5jb20nLFxuICAgIFVzZXJUeXBlOiAwLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTaGFyZVBvaW50JyxcbiAgICBDbGllbnRJUDogJzE5MC4xNi45LjE3NicsXG4gICAgT2JqZWN0SWQ6ICdodHRwczovL3dhenVoLnNoYXJlcG9pbnQuY29tL3NpdGVzL1Rlc3RTaGFyZVBvaW50L1NpdGVQYWdlcy9Ib21lLmFzcHgnLFxuICAgIFVzZXJJZDogJ2Zha2VAZW1haWwubm90JyxcbiAgICBDb3JyZWxhdGlvbklkOiAnNjJkMWM5OWYtZDA5Yy0yMDAwLWRmMTMtMzdkZGY0ODBlNzE3JyxcbiAgICBEb05vdERpc3RyaWJ1dGVFdmVudDogdHJ1ZSxcbiAgICBFdmVudFNvdXJjZTogJ1NoYXJlUG9pbnQnLFxuICAgIEl0ZW1UeXBlOiAnRmlsZScsXG4gICAgTGlzdElkOiAnZTRjOWNlMmUtZDhjMi00NjhlLWJhZjUtZjM2MmY4YzJmMmYzJyxcbiAgICBMaXN0SXRlbVVuaXF1ZUlkOiAnMzZkYjMxNjgtYzFiMi00NGU5LTlmZmQtZTlhOGUwNGJiMmY1JyxcbiAgICBTaXRlOiAnZGQ1OGVmMDgtZmFlYS00Y2I1LTg0N2EtMzViYjVjMDFlNzU3JyxcbiAgICBVc2VyQWdlbnQ6XG4gICAgICAnTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkwLjAuNDQzMC4yMTIgU2FmYXJpLzUzNy4zNicsXG4gICAgV2ViSWQ6ICcwMGMzMjU1NS1lMGQ4LTQyNWYtOWZiZC1lZjU1MzliZmVjZjcnLFxuICAgIFNvdXJjZUZpbGVFeHRlbnNpb246ICdhc3B4JyxcbiAgICBTaXRlVXJsOiAnaHR0cHM6Ly93YXp1aC5zaGFyZXBvaW50LmNvbS9zaXRlcy9UZXN0U2hhcmVQb2ludC8nLFxuICAgIFNvdXJjZUZpbGVOYW1lOiAnSG9tZS5hc3B4JyxcbiAgICBTb3VyY2VSZWxhdGl2ZVVybDogJ1NpdGVQYWdlcycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTIwVDE3OjU3OjAzJyxcbiAgICBJZDogJzU1MWZkN2Q1LWJhYzEtNGJiNC0xMWQyLTA4ZDkxYmI4YWM5ZScsXG4gICAgT3BlcmF0aW9uOiAnRmlsZUFjY2Vzc2VkRXh0ZW5kZWQnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiA2LFxuICAgIFVzZXJLZXk6ICdpOjBoLmZ8bWVtYmVyc2hpcHwxMDAzMjAwMTQwODBkM2FkQGxpdmUuY29tJyxcbiAgICBVc2VyVHlwZTogMCxcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnU2hhcmVQb2ludCcsXG4gICAgQ2xpZW50SVA6ICcxOTAuMTYuOS4xNzYnLFxuICAgIE9iamVjdElkOlxuICAgICAgJ2h0dHBzOi8vd2F6dWguc2hhcmVwb2ludC5jb20vc2l0ZXMvVGVzdFNoYXJlUG9pbnQvU2hhcmVkIERvY3VtZW50cy9Gb3Jtcy9BbGxJdGVtcy5hc3B4JyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgQ29ycmVsYXRpb25JZDogJzk0ZDFjOTlmLTIwZWItMjAwMC1kZjEzLTM1NzQ2ZDAyOTExZScsXG4gICAgRXZlbnRTb3VyY2U6ICdTaGFyZVBvaW50JyxcbiAgICBJdGVtVHlwZTogJ0ZpbGUnLFxuICAgIExpc3RJZDogJ2ZkMmViYWYwLTkwMGItNGRmZi04ZmMyLWQzNDhiZTUxZTY3NycsXG4gICAgTGlzdEl0ZW1VbmlxdWVJZDogJzNjOWQ4OTQzLTg0NmUtNDFmMy1hNjQ3LTcyYTVlNGUzZGVjZicsXG4gICAgU2l0ZTogJ2RkNThlZjA4LWZhZWEtNGNiNS04NDdhLTM1YmI1YzAxZTc1NycsXG4gICAgVXNlckFnZW50OlxuICAgICAgJ01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS85MC4wLjQ0MzAuMjEyIFNhZmFyaS81MzcuMzYnLFxuICAgIFdlYklkOiAnMDBjMzI1NTUtZTBkOC00MjVmLTlmYmQtZWY1NTM5YmZlY2Y3JyxcbiAgICBTb3VyY2VGaWxlRXh0ZW5zaW9uOiAnYXNweCcsXG4gICAgU2l0ZVVybDogJ2h0dHBzOi8vd2F6dWguc2hhcmVwb2ludC5jb20vc2l0ZXMvVGVzdFNoYXJlUG9pbnQvJyxcbiAgICBTb3VyY2VGaWxlTmFtZTogJ0FsbEl0ZW1zLmFzcHgnLFxuICAgIFNvdXJjZVJlbGF0aXZlVXJsOiAnU2hhcmVkIERvY3VtZW50cy9Gb3JtcycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTIwVDE3OjU5OjU1JyxcbiAgICBJZDogJ2ViMWYwOTExLTliZWQtNGYxNS0xMGU1LTA4ZDkxYmI5MTM3MicsXG4gICAgT3BlcmF0aW9uOiAnU2l0ZURlbGV0ZWQnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiA2LFxuICAgIFVzZXJLZXk6ICdTLTEtMC0wJyxcbiAgICBVc2VyVHlwZTogNCxcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnU2hhcmVQb2ludCcsXG4gICAgQ2xpZW50SVA6ICcnLFxuICAgIE9iamVjdElkOiAnaHR0cHM6Ly93YXp1aC5zaGFyZXBvaW50LmNvbS9zaXRlcy9UZXN0U2hhcmVQb2ludCcsXG4gICAgVXNlcklkOiAnQUFEIHRvIFNoYXJlUG9pbnQgU3luYycsXG4gICAgQ29ycmVsYXRpb25JZDogJ2JlZDFjOTlmLTIwZWUtMjAwMC1kZjEzLTMwNmNiNjgwM2M5MicsXG4gICAgRXZlbnRTb3VyY2U6ICdTaGFyZVBvaW50JyxcbiAgICBJdGVtVHlwZTogJ1dlYicsXG4gICAgTGlzdEl0ZW1VbmlxdWVJZDogJzAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCcsXG4gICAgU2l0ZTogJ2RkNThlZjA4LWZhZWEtNGNiNS04NDdhLTM1YmI1YzAxZTc1NycsXG4gICAgVXNlckFnZW50OiAnJyxcbiAgICBXZWJJZDogJzAwYzMyNTU1LWUwZDgtNDI1Zi05ZmJkLWVmNTUzOWJmZWNmNycsXG4gICAgRGVzdGluYXRpb25GaWxlRXh0ZW5zaW9uOiAnJyxcbiAgICBTb3VyY2VGaWxlRXh0ZW5zaW9uOiAnJyxcbiAgICBEZXN0aW5hdGlvbkZpbGVOYW1lOiAnVGVzdFNoYXJlUG9pbnQnLFxuICAgIERlc3RpbmF0aW9uUmVsYXRpdmVVcmw6ICcuLi8uLi9odHRwczovL3dhenVoLnNoYXJlcG9pbnQuY29tL3NpdGVzJyxcbiAgICBTaXRlVXJsOiAnaHR0cHM6Ly93YXp1aC5zaGFyZXBvaW50LmNvbS9zaXRlcy9UZXN0U2hhcmVQb2ludC8nLFxuICAgIFNvdXJjZUZpbGVOYW1lOiAnVGVzdFNoYXJlUG9pbnQnLFxuICAgIFNvdXJjZVJlbGF0aXZlVXJsOiAnLi4nLFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0yMFQxNzo1OToxMScsXG4gICAgSWQ6ICcwZDIwYTNlMS1lOWNiLTQzNmMtNzk5Zi0wOGQ5MWJiOGY5MmYnLFxuICAgIE9wZXJhdGlvbjogJ1BhZ2VWaWV3ZWRFeHRlbmRlZCcsXG4gICAgT3JnYW5pemF0aW9uSWQ6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgIFJlY29yZFR5cGU6IDQsXG4gICAgVXNlcktleTogJ2k6MGguZnxtZW1iZXJzaGlwfDEwMDMyMDAxNDA4MGQzYWRAbGl2ZS5jb20nLFxuICAgIFVzZXJUeXBlOiAwLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdTaGFyZVBvaW50JyxcbiAgICBDbGllbnRJUDogJzE5MC4xNi45LjE3NicsXG4gICAgT2JqZWN0SWQ6XG4gICAgICAnaHR0cHM6Ly93YXp1aC5zaGFyZXBvaW50LmNvbS9zaXRlcy9UZXN0U2hhcmVQb2ludC9fbGF5b3V0cy8xNS9vbmxpbmUvaGFuZGxlcnMvU3BvU3VpdGVMaW5rcy5hc2h4JyxcbiAgICBVc2VySWQ6ICdmYWtlQGVtYWlsLm5vdCcsXG4gICAgQ29ycmVsYXRpb25JZDogJ2I0ZDFjOTlmLTAwNDMtMjAwMC1kYTgyLTQxYjYzZTFkOTFmNCcsXG4gICAgRXZlbnRTb3VyY2U6ICdTaGFyZVBvaW50JyxcbiAgICBJdGVtVHlwZTogJ1BhZ2UnLFxuICAgIFNpdGU6ICdkZDU4ZWYwOC1mYWVhLTRjYjUtODQ3YS0zNWJiNWMwMWU3NTcnLFxuICAgIFVzZXJBZ2VudDpcbiAgICAgICdNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvOTAuMC40NDMwLjIxMiBTYWZhcmkvNTM3LjM2JyxcbiAgICBXZWJJZDogJzAwYzMyNTU1LWUwZDgtNDI1Zi05ZmJkLWVmNTUzOWJmZWNmNycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTIwVDE3OjQ0OjI3JyxcbiAgICBJZDogJzMwZWYyZjcwLWExMmQtNGIzMS0xZTcwLTA4ZDkxYmI2ZWEyZScsXG4gICAgT3BlcmF0aW9uOiAnU2V0LU1haWxib3gnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiAxLFxuICAgIFJlc3VsdFN0YXR1czogJ1RydWUnLFxuICAgIFVzZXJLZXk6ICdTcG9vbHNQcm92aXNpb25pbmctQXBwbGljYXRpb25BY2NvdW50QGV1cnByZDA0LnByb2Qub3V0bG9vay5jb20nLFxuICAgIFVzZXJUeXBlOiAzLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdFeGNoYW5nZScsXG4gICAgQ2xpZW50SVA6ICc1Mi4yMzMuMjM3LjE0MTo0MDYzOCcsXG4gICAgT2JqZWN0SWQ6XG4gICAgICAnRVVSUFIwNEEwMTAucHJvZC5vdXRsb29rLmNvbS9NaWNyb3NvZnQgRXhjaGFuZ2UgSG9zdGVkIE9yZ2FuaXphdGlvbnMvd2F6dWgudGVzdHl0ZXN0LmNvbS90b21hcy50dXJpbmEnLFxuICAgIFVzZXJJZDogJ1Nwb29sc1Byb3Zpc2lvbmluZy1BcHBsaWNhdGlvbkFjY291bnRAZXVycHJkMDQucHJvZC5vdXRsb29rLmNvbScsXG4gICAgQXBwSWQ6ICc2MTEwOTczOC03ZDJiLTRhMGItOWZlMy02NjBiMWZmODM1MDUnLFxuICAgIENsaWVudEFwcElkOiAnJyxcbiAgICBFeHRlcm5hbEFjY2VzczogdHJ1ZSxcbiAgICBPcmdhbml6YXRpb25OYW1lOiAnd2F6dWgudGVzdHl0ZXN0LmNvbScsXG4gICAgT3JpZ2luYXRpbmdTZXJ2ZXI6ICdBTTlQUjA0TUI4OTg2ICgxNS4yMC40MTUwLjAyMyknLFxuICAgIFBhcmFtZXRlcnM6IFtcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ0lkZW50aXR5JyxcbiAgICAgICAgVmFsdWU6XG4gICAgICAgICAgJ01HWmxZVFJsTURNdE9ERTBOaTAwTlROaUxXSTRPRGt0TlRSaU5HSmtNVEUxTmpWaVhHSmtZbUk0TWpNMkxUQm1ORGd0Tkdaak5pMDVaamMzTFRreE5HTmtZMk13TW1Jell3MicsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnUmVzb3VyY2VFbWFpbEFkZHJlc3NlcycsXG4gICAgICAgIFZhbHVlOiAnVHJ1ZScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnQnlwYXNzTGl2ZUlkJyxcbiAgICAgICAgVmFsdWU6ICdUcnVlJyxcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdGb3JjZScsXG4gICAgICAgIFZhbHVlOiAnVHJ1ZScsXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBOYW1lOiAnRG9tYWluQ29udHJvbGxlcicsXG4gICAgICAgIFZhbHVlOiAnSEUxUFIwNEEwMTBEQzAzLkVVUlBSMDRBMDEwLnByb2Qub3V0bG9vay5jb20nLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ0VtYWlsQWRkcmVzc2VzJyxcbiAgICAgICAgVmFsdWU6XG4gICAgICAgICAgJ1NJUDpmYWtlQGVtYWlsLm5vdDtTTVRQOmZha2VAZW1haWwubm90O1NQTzpTUE9fZjQ5ZmVhZTQtMDMzZC00MDI4LTk3ZDEtM2FjZDU1MzQxZjY5QFNQT18wZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWInLFxuICAgICAgfSxcbiAgICBdLFxuICAgIFNlc3Npb25JZDogJycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTIwVDE3OjQ1OjU5JyxcbiAgICBJZDogJzQ4YzAwOTMwLWIyNWQtNGNjYy1jY2IzLTA4ZDkxYmI3MjBmNicsXG4gICAgT3BlcmF0aW9uOiAnTW9kaWZ5Rm9sZGVyUGVybWlzc2lvbnMnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiAyLFxuICAgIFJlc3VsdFN0YXR1czogJ1N1Y2NlZWRlZCcsXG4gICAgVXNlcktleTogJ1MtMS01LTE4JyxcbiAgICBVc2VyVHlwZTogMixcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnRXhjaGFuZ2UnLFxuICAgIENsaWVudElQOiAnOjoxJyxcbiAgICBVc2VySWQ6ICdTLTEtNS0xOCcsXG4gICAgQ2xpZW50SVBBZGRyZXNzOiAnOjoxJyxcbiAgICBDbGllbnRJbmZvU3RyaW5nOiAnQ2xpZW50PVdlYlNlcnZpY2VzO0FjdGlvbj1Db25maWd1cmVHcm91cE1haWxib3gnLFxuICAgIEV4dGVybmFsQWNjZXNzOiB0cnVlLFxuICAgIEludGVybmFsTG9nb25UeXBlOiAxLFxuICAgIExvZ29uVHlwZTogMSxcbiAgICBMb2dvblVzZXJTaWQ6ICdTLTEtNS0xOCcsXG4gICAgTWFpbGJveEd1aWQ6ICdmYzEwOGI0NS05ZDUxLTRiODctYTQ3My05ZDVhMGU0MDQ5NjYnLFxuICAgIE1haWxib3hPd25lck1hc3RlckFjY291bnRTaWQ6ICdTLTEtNS0xMCcsXG4gICAgTWFpbGJveE93bmVyU2lkOiAnUy0xLTUtMjEtMjk4NjU2NTgwNS0xODM1MjY1NTUwLTEzODM1NzQwNzMtMjA3NDMwNjcnLFxuICAgIE1haWxib3hPd25lclVQTjogJ1Rlc3RTaGFyZVBvaW50QHdhenVoLmNvbScsXG4gICAgT3JnYW5pemF0aW9uTmFtZTogJ3dhenVoLnRlc3R5dGVzdC5jb20nLFxuICAgIE9yaWdpbmF0aW5nU2VydmVyOiAnQVM4UFIwNE1CODQ2NSAoMTUuMjAuNDE1MC4wMjMpXFxyXFxuJyxcbiAgICBJdGVtOiB7XG4gICAgICBJZDogJ0xnQUFBQUE2dFZoYmEzSldTYUdta3k3LzdPdmZBUURSd0tjNDdjMXNUNFdhYWI2TzR6YlBBQUFBQUFFTkFBQUMnLFxuICAgICAgUGFyZW50Rm9sZGVyOiB7XG4gICAgICAgIElkOiAnTGdBQUFBQTZ0VmhiYTNKV1NhR21reTcvN092ZkFRRFJ3S2M0N2Mxc1Q0V2FhYjZPNHpiUEFBQUFBQUVOQUFBQycsXG4gICAgICAgIE1lbWJlclJpZ2h0czpcbiAgICAgICAgICAnUmVhZEFueSwgQ3JlYXRlLCBFZGl0T3duZWQsIERlbGV0ZU93bmVkLCBFZGl0QW55LCBEZWxldGVBbnksIFZpc2libGUsIEZyZWVCdXN5U2ltcGxlLCBGcmVlQnVzeURldGFpbGVkJyxcbiAgICAgICAgTWVtYmVyU2lkOiAnUy0xLTgtNDIyODk0MjY2MS0xMjY3MTc4ODMzLTE1MjAyNjgxOTYtMTcxNjA3NjU1OC0xJyxcbiAgICAgICAgTWVtYmVyVXBuOiAnTWVtYmVyQGxvY2FsJyxcbiAgICAgICAgTmFtZTogJ0NhbGVuZGFyJyxcbiAgICAgICAgUGF0aDogJ1xcXFxDYWxlbmRhcicsXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTIwVDE3OjQ1OjU4JyxcbiAgICBJZDogJ2JiMDNiNDhlLTYwOWQtNDc3Yi1jYjgwLTA4ZDkxYmI3MjA3NycsXG4gICAgT3BlcmF0aW9uOiAnQ3JlYXRlJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogMixcbiAgICBSZXN1bHRTdGF0dXM6ICdTdWNjZWVkZWQnLFxuICAgIFVzZXJLZXk6ICdTLTEtNS0xOCcsXG4gICAgVXNlclR5cGU6IDIsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ0V4Y2hhbmdlJyxcbiAgICBDbGllbnRJUDogJzo6MScsXG4gICAgVXNlcklkOiAnUy0xLTUtMTgnLFxuICAgIENsaWVudElQQWRkcmVzczogJzo6MScsXG4gICAgQ2xpZW50SW5mb1N0cmluZzogJ0NsaWVudD1XZWJTZXJ2aWNlcztBY3Rpb249Q29uZmlndXJlR3JvdXBNYWlsYm94JyxcbiAgICBFeHRlcm5hbEFjY2VzczogdHJ1ZSxcbiAgICBJbnRlcm5hbExvZ29uVHlwZTogMSxcbiAgICBMb2dvblR5cGU6IDEsXG4gICAgTG9nb25Vc2VyU2lkOiAnUy0xLTUtMTgnLFxuICAgIE1haWxib3hHdWlkOiAnZmMxMDhiNDUtOWQ1MS00Yjg3LWE0NzMtOWQ1YTBlNDA0OTY2JyxcbiAgICBNYWlsYm94T3duZXJNYXN0ZXJBY2NvdW50U2lkOiAnUy0xLTUtMTAnLFxuICAgIE1haWxib3hPd25lclNpZDogJ1MtMS01LTIxLTI5ODY1NjU4MDUtMTgzNTI2NTU1MC0xMzgzNTc0MDczLTIwNzQzMDY3JyxcbiAgICBNYWlsYm94T3duZXJVUE46ICdUZXN0U2hhcmVQb2ludEB3YXp1aC5jb20nLFxuICAgIE9yZ2FuaXphdGlvbk5hbWU6ICd3YXp1aC50ZXN0eXRlc3QuY29tJyxcbiAgICBPcmlnaW5hdGluZ1NlcnZlcjogJ0FTOFBSMDRNQjg0NjUgKDE1LjIwLjQxNTAuMDIzKVxcclxcbicsXG4gICAgSXRlbToge1xuICAgICAgQXR0YWNobWVudHM6XG4gICAgICAgICd3YXJtaW5nX2VtYWlsXzAzXzIwMTdfY2FsZW5kYXIucG5nICg2NDZiKTsgd2FybWluZ19lbWFpbF8wM18yMDE3X2NvbnZlcnNhdGlvbi5wbmcgKDY2MWIpOyB3YXJtaW5nX2VtYWlsXzAzXzIwMTdfbGlua3MucG5nICgxNDUwYik7IGdvb2dsZV9wbGF5X3N0b3JlX2JhZGdlLnBuZyAoNDg3MWIpOyBhcHBsZV9zdG9yZV9iYWRnZS5wbmcgKDQ0OTNiKTsgd2luZG93c19zdG9yZV9iYWRnZS5wbmcgKDM3MjhiKTsgd2FybWluZ19lbWFpbF8wM18yMDE3X2ZpbGVzLnBuZyAoODU2Yik7IHdhcm1pbmdfZW1haWxfMDNfMjAxN19zaGFyZVBvaW50LnBuZyAoMTQ3OWIpJyxcbiAgICAgIElkOlxuICAgICAgICAnUmdBQUFBQTZ0VmhiYTNKV1NhR21reTcvN092ZkJ3RFJ3S2M0N2Mxc1Q0V2FhYjZPNHpiUEFBQUFBQUVNQUFEUndLYzQ3YzFzVDRXYWFiNk80emJQQUFBQUFBazlBQUFKJyxcbiAgICAgIEludGVybmV0TWVzc2FnZUlkOlxuICAgICAgICAnPEFTOFBSMDRNQjg0NjU0MjEwNkQzOTM5RjJEMTk1MkQwNUQzMkE5QEFTOFBSMDRNQjg0NjUuZXVycHJkMDQucHJvZC5vdXRsb29rLmNvbT4nLFxuICAgICAgSXNSZWNvcmQ6IGZhbHNlLFxuICAgICAgUGFyZW50Rm9sZGVyOiB7XG4gICAgICAgIElkOiAnTGdBQUFBQTZ0VmhiYTNKV1NhR21reTcvN092ZkFRRFJ3S2M0N2Mxc1Q0V2FhYjZPNHpiUEFBQUFBQUVNQUFBQicsXG4gICAgICAgIFBhdGg6ICdcXFxcSW5ib3gnLFxuICAgICAgfSxcbiAgICAgIFN1YmplY3Q6ICdUaGUgbmV3IFRlc3RTaGFyZVBvaW50IGdyb3VwIGlzIHJlYWR5JyxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgQ3JlYXRpb25UaW1lOiAnMjAyMS0wNS0yMFQxNzo1OTo1OScsXG4gICAgSWQ6ICdlODU1ZmIxMi0yZDQ4LTQ1ZjMtYWM4ZC0wOGQ5MWJiOTE1NjknLFxuICAgIE9wZXJhdGlvbjogJ1JlbW92ZS1VbmlmaWVkR3JvdXAnLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiAxLFxuICAgIFJlc3VsdFN0YXR1czogJ1RydWUnLFxuICAgIFVzZXJLZXk6ICdOVCBBVVRIT1JJVFlcXFxcU1lTVEVNICh3M3dwKScsXG4gICAgVXNlclR5cGU6IDIsXG4gICAgVmVyc2lvbjogMSxcbiAgICBXb3JrbG9hZDogJ0V4Y2hhbmdlJyxcbiAgICBDbGllbnRJUDogJ1syYTAxOjExMTpmNDAyOmFjMDA6OmYxMzRdOjUxNTE0JyxcbiAgICBPYmplY3RJZDogJ1Rlc3RTaGFyZVBvaW50X2I0N2UwNmJmLTg5NWQtNDhjNC04YWU0LWEwZmRjNjBlYzI0OScsXG4gICAgVXNlcklkOiAnTlQgQVVUSE9SSVRZXFxcXFNZU1RFTSAodzN3cCknLFxuICAgIEFwcElkOiAnMDAwMDAwMDMtMDAwMC0wZmYxLWNlMDAtMDAwMDAwMDAwMDAwJyxcbiAgICBDbGllbnRBcHBJZDogJzAwMDAwMDAzLTAwMDAtMGZmMS1jZTAwLTAwMDAwMDAwMDAwMCcsXG4gICAgRXh0ZXJuYWxBY2Nlc3M6IGZhbHNlLFxuICAgIE9yZ2FuaXphdGlvbk5hbWU6ICd3YXp1aC50ZXN0eXRlc3QuY29tJyxcbiAgICBPcmlnaW5hdGluZ1NlcnZlcjogJ1ZJMVBSMDRNQjYxMjUgKDE1LjIwLjQxMjkuMDMzKScsXG4gICAgUGFyYW1ldGVyczogW1xuICAgICAge1xuICAgICAgICBOYW1lOiAnSWRlbnRpdHknLFxuICAgICAgICBWYWx1ZTogJ2I0N2UwNmJmLTg5NWQtNDhjNC04YWU0LWEwZmRjNjBlYzI0OScsXG4gICAgICB9LFxuICAgIF0sXG4gICAgU2Vzc2lvbklkOiAnJyxcbiAgfSxcbiAge1xuICAgIENyZWF0aW9uVGltZTogJzIwMjEtMDUtMjBUMTg6MDQ6MzcnLFxuICAgIElkOiAnZjExMWM4MmMtNzk2MS00NzNkLTExMmEtMDhkOTFiYjliYjkxJyxcbiAgICBPcGVyYXRpb246ICdTZXQtVW5pZmllZEdyb3VwJyxcbiAgICBPcmdhbml6YXRpb25JZDogJzBmZWE0ZTAzLTgxNDYtNDUzYi1iODg5LTU0YjRiZDExNTY1YicsXG4gICAgUmVjb3JkVHlwZTogMSxcbiAgICBSZXN1bHRTdGF0dXM6ICdUcnVlJyxcbiAgICBVc2VyS2V5OiAnU3Bvb2xzUHJvdmlzaW9uaW5nLUFwcGxpY2F0aW9uQWNjb3VudEBldXJwcmQwNC5wcm9kLm91dGxvb2suY29tJyxcbiAgICBVc2VyVHlwZTogMyxcbiAgICBWZXJzaW9uOiAxLFxuICAgIFdvcmtsb2FkOiAnRXhjaGFuZ2UnLFxuICAgIENsaWVudElQOiAnNTEuMTQ0LjMzLjE0OjU4ODQ5JyxcbiAgICBPYmplY3RJZDpcbiAgICAgICdFVVJQUjA0QTAxMC5wcm9kLm91dGxvb2suY29tL01pY3Jvc29mdCBFeGNoYW5nZSBIb3N0ZWQgT3JnYW5pemF0aW9ucy93YXp1aC50ZXN0eXRlc3QuY29tL1NvZnQgRGVsZXRlZCBPYmplY3RzL1Rlc3RTaGFyZVBvaW50X2I0N2UwNmJmLTg5NWQtNDhjNC04YWU0LWEwZmRjNjBlYzI0OScsXG4gICAgVXNlcklkOiAnU3Bvb2xzUHJvdmlzaW9uaW5nLUFwcGxpY2F0aW9uQWNjb3VudEBldXJwcmQwNC5wcm9kLm91dGxvb2suY29tJyxcbiAgICBBcHBJZDogJzYxMTA5NzM4LTdkMmItNGEwYi05ZmUzLTY2MGIxZmY4MzUwNScsXG4gICAgQ2xpZW50QXBwSWQ6ICcnLFxuICAgIEV4dGVybmFsQWNjZXNzOiB0cnVlLFxuICAgIE9yZ2FuaXphdGlvbk5hbWU6ICd3YXp1aC50ZXN0eXRlc3QuY29tJyxcbiAgICBPcmlnaW5hdGluZ1NlcnZlcjogJ1ZJMVBSMDQwMk1CMzMyNiAoMTUuMjAuNDEyOS4wMzMpJyxcbiAgICBQYXJhbWV0ZXJzOiBbXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdJZGVudGl0eScsXG4gICAgICAgIFZhbHVlOlxuICAgICAgICAgICdNR1psWVRSbE1ETXRPREUwTmkwME5UTmlMV0k0T0RrdE5UUmlOR0prTVRFMU5qVmlYREZsWWpGak5qWmhMVFJoWVdRdE5HWTJNaTA0TmpBekxUZGpNRFJrWlRJeFlXRTNNZzInLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ0VtYWlsQWRkcmVzc2VzJyxcbiAgICAgICAgVmFsdWU6ICdzbXRwOlRlc3RTaGFyZVBvaW50QHdhenVoLnRlc3R5dGVzdC5jb207U01UUDpUZXN0U2hhcmVQb2ludEB3YXp1aC5jb20nLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ0luY2x1ZGVTb2Z0RGVsZXRlZE9iamVjdHMnLFxuICAgICAgICBWYWx1ZTogJ1RydWUnLFxuICAgICAgfSxcbiAgICBdLFxuICAgIFNlc3Npb25JZDogJycsXG4gIH0sXG4gIHtcbiAgICBDcmVhdGlvblRpbWU6ICcyMDIxLTA1LTIwVDE4OjU5OjQ5JyxcbiAgICBJZDogJzMyMjI5MTE0LWUzNTctNGI1Ni05ZDA4LTA4ZDkxYmMxNzE3YycsXG4gICAgT3BlcmF0aW9uOiAnU2V0LVVzZXInLFxuICAgIE9yZ2FuaXphdGlvbklkOiAnMGZlYTRlMDMtODE0Ni00NTNiLWI4ODktNTRiNGJkMTE1NjViJyxcbiAgICBSZWNvcmRUeXBlOiAxLFxuICAgIFJlc3VsdFN0YXR1czogJ1RydWUnLFxuICAgIFVzZXJLZXk6ICdOVCBBVVRIT1JJVFlcXFxcU1lTVEVNIChNaWNyb3NvZnQuRXhjaGFuZ2UuTWFuYWdlbWVudC5Gb3J3YXJkU3luYyknLFxuICAgIFVzZXJUeXBlOiAzLFxuICAgIFZlcnNpb246IDEsXG4gICAgV29ya2xvYWQ6ICdFeGNoYW5nZScsXG4gICAgT2JqZWN0SWQ6XG4gICAgICAnRVVSUFIwNEEwMTAucHJvZC5vdXRsb29rLmNvbS9NaWNyb3NvZnQgRXhjaGFuZ2UgSG9zdGVkIE9yZ2FuaXphdGlvbnMvd2F6dWgudGVzdHl0ZXN0LmNvbS90b21hcy50dXJpbmEnLFxuICAgIFVzZXJJZDogJ05UIEFVVEhPUklUWVxcXFxTWVNURU0gKE1pY3Jvc29mdC5FeGNoYW5nZS5NYW5hZ2VtZW50LkZvcndhcmRTeW5jKScsXG4gICAgQXBwSWQ6ICcnLFxuICAgIENsaWVudEFwcElkOiAnJyxcbiAgICBFeHRlcm5hbEFjY2VzczogdHJ1ZSxcbiAgICBPcmdhbml6YXRpb25OYW1lOiAnd2F6dWgudGVzdHl0ZXN0LmNvbScsXG4gICAgT3JpZ2luYXRpbmdTZXJ2ZXI6ICdEQjhQUjA0TUI3MDY1ICgxNS4yMC40MTUwLjAyMyknLFxuICAgIFBhcmFtZXRlcnM6IFtcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ0lkZW50aXR5JyxcbiAgICAgICAgVmFsdWU6ICcwZmVhNGUwMy04MTQ2LTQ1M2ItYjg4OS01NGI0YmQxMTU2NWJcXFxcYmRiYjgyMzYtMGY0OC00ZmM2LTlmNzctOTE0Y2RjYzAyYjNjJyxcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdTeW5jTWFpbGJveExvY2F0aW9uR3VpZHMnLFxuICAgICAgICBWYWx1ZTogJ1RydWUnLFxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgTmFtZTogJ0Vycm9yQWN0aW9uJyxcbiAgICAgICAgVmFsdWU6ICdTdG9wJyxcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIE5hbWU6ICdXYXJuaW5nQWN0aW9uJyxcbiAgICAgICAgVmFsdWU6ICdTaWxlbnRseUNvbnRpbnVlJyxcbiAgICAgIH0sXG4gICAgXSxcbiAgfSxcbl07XG4iXX0=