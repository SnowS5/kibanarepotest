"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.source = exports.remoteIpDetails = exports.region = exports.networkConnection = exports.instanceId = exports.instanceDetails = exports.iamPolicyGrantGlobal = exports.guarddutyPortProbe = exports.buckets = exports.apiCall = exports.accountId = void 0;

/*
 * Wazuh app - AWS sample data
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
// Amazon AWS services
const source = ["guardduty", "cloudtrail", "vpcflow", "config"];
exports.source = source;
const accountId = ["186157501624", "117521235382", "150447125201", "18773455640", "186154171780", "250141701015"];
exports.accountId = accountId;
const region = ["eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "eu-central-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2", "me-south-1", "ap-east-1", "ap-east-2", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1"]; // https://docs.aws.amazon.com/es_es/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-regions

exports.region = region;
const buckets = ["aws-sample-bucket-1", "aws-sample-bucket-2", "aws-sample-bucket-3", "aws-sample-bucket-4", "aws-sample-bucket-5", "aws-sample-bucket-6", "aws-sample-bucket-7", "aws-sample-bucket-8", "aws-sample-bucket-9"];
exports.buckets = buckets;
const instanceId = ['i-060bb01699dddc20c', 'i-060bb020479bedc20w', 'i-070eb020479bebf20a', 'i-070eb015479befb15d', 'i-057eb060779fdae15b'];
exports.instanceId = instanceId;
const remoteIpDetails = [{
  country: {
    countryName: "Mexico"
  },
  city: {
    cityName: "Mérida"
  },
  geoLocation: {
    lon: "-89.616700",
    lat: "20.950000"
  },
  organization: {
    asnOrg: "Internet Mexico Company",
    org: "Internet Mexico Company",
    isp: "Internet Mexico Company",
    asn: "4257"
  },
  ipAddressV4: "160.0.14.40"
}, {
  country: {
    countryName: "Italy"
  },
  city: {
    cityName: "Savona"
  },
  geoLocation: {
    lon: "8.477200",
    lat: "44.309000"
  },
  organization: {
    asnOrg: "Speedweb",
    org: "Speedweb",
    isp: "Speedweb",
    asn: "42784"
  },
  ipAddressV4: "2.25.80.45"
}, {
  country: {
    countryName: "Mexico"
  },
  city: {
    cityName: "Colima"
  },
  geoLocation: {
    lon: "-103.714500",
    lat: "19.266800"
  },
  organization: {
    asnOrg: "Internet Mexico Company",
    org: "Internet Mexico Company",
    isp: "Internet Mexico Company",
    asn: "4257"
  },
  ipAddressV4: "187.234.16.206"
}, {
  country: {
    countryName: "Netherlands"
  },
  city: {
    cityName: "Amsterdam"
  },
  geoLocation: {
    lon: "4.889700",
    lat: "52.374000"
  },
  organization: {
    asnOrg: "Netherlands Telecom",
    org: "Netherlands Telecom",
    isp: "Netherlands Telecom",
    asn: "40070"
  },
  ipAddressV4: "160.0.14.40"
}, {
  country: {
    "countryName": "Italy"
  },
  city: {
    cityName: "Palermo"
  },
  geoLocation: {
    lon: "13.334100",
    lat: "38.129000"
  },
  organization: {
    asnOrg: "Net Connections",
    org: "Net Connections",
    isp: "Net Connections",
    asn: "1547"
  },
  ipAddressV4: "75.0.101.245"
}, {
  country: {
    countryName: "United States"
  },
  city: {
    cityName: "Panama City"
  },
  geoLocation: {
    lon: "-85.669600",
    lat: "30.190900"
  },
  organization: {
    asnOrg: "Internet Innovations",
    org: "Intenet Innovations",
    isp: "Intenet Innovations",
    asn: "4252"
  },
  ipAddressV4: "70.24.101.214"
}];
exports.remoteIpDetails = remoteIpDetails;
const instanceDetails = [{
  "launchTime": "2020-04-22T11:17:08Z",
  "instanceId": "i-0b0b8b34a48c8f1c4",
  "networkInterfaces": {
    "networkInterfaceId": "eni-01e777fb9acd548e4",
    "subnetId": "subnet-7930da22",
    "vpcId": "vpc-68e3c60f",
    "privateDnsName": "ip-10-0-2-2.ec2.internal",
    "publicIp": "40.220.125.204",
    "publicDnsName": "ec2-40.220.125.204.compute-1.amazonaws.com",
    "privateIpAddress": "10.0.2.2"
  },
  "instanceState": "running",
  "imageId": "ami-0ff8a91507f77f900",
  "instanceType": "t2.small",
  "imageDescription": "Amazon Linux AMI 2018.03.0.20180811 x86_64 HVM GP2",
  "iamInstanceProfile": {
    "id": "AIPAJGAZMFPZHKIBOCBIG",
    "arn": "arn:aws:iam::{data.aws.accountId}:instance-profile/opsworks-web-production"
  },
  "availabilityZone": "us-east-1a"
}, {
  "launchTime": "2019-03-22T14:15:41Z",
  "instanceId": "i-0cab4a083d57dc400",
  "networkInterfaces": {
    "networkInterfaceId": "eni-0bb465b2d939dbda6",
    "subnetId": "subnet-6b1d6203",
    "vpcId": "vpc-921e61fa",
    "privateDnsName": "ip-10-0-0-1.ec2.internal",
    "publicIp": "54.90.48.38",
    "publicDnsName": "ec2-54.90.48.38.compute-1.amazonaws.com",
    "privateIpAddress": "10.0.0.1"
  },
  "instanceState": "running",
  "imageId": "ami-09ae67bbfcd740875",
  "instanceType": "a1.medium",
  "imageDescription": "Canonical, Ubuntu, 18.04 LTS, UNSUPPORTED daily arm64 bionic image build on 2019-02-12",
  "productCodes": {
    "productCodeId": "zud1u4kjmxu2j2jf0n36bqa",
    "productCodeType": "marketplace"
  },
  "iamInstanceProfile": {
    // FIXME
    "id": "AIPAJGAZMFPZHKIBOUFGA",
    "arn": "arn:aws:iam::{data.aws.accountId}:instance-profile/opsworks-web-production"
  },
  "availabilityZone": "us-east-1e"
}];
exports.instanceDetails = instanceDetails;
const guarddutyPortProbe = {
  data: {
    aws: {
      severity: "2",
      schemaVersion: "2.0",
      resource: {
        // instanceDetails
        resourceType: "Instance"
      },
      description: "EC2 instance has an unprotected port which is being probed by a known malicious host.",
      source: "guardduty",
      type: "Recon:EC2/PortProbeUnprotectedPort",
      title: "Unprotected port on EC2 instance {data.aws.resource.instanceDetails.instanceId} is being probed.",
      // accountId: "166157441623",
      // createdAt: "2019-07-31T16:31:14.739Z",
      partition: "aws",
      service: {
        archived: "false",
        resourceRole: "TARGET",
        detectorId: "cab38390b400c06fb2897dfcebffb80d",
        // eventFirstSeen: "2019-07-31T16:18:08Z",
        // eventLastSeen: "2020-04-22T04:11:01Z",
        additionalInfo: {
          threatListName: "ProofPoint",
          threatName: "Scanner"
        },
        count: "2594",
        action: {
          actionType: "PORT_PROBE",
          portProbeAction: {
            blocked: "false",
            portProbeDetails: {
              localPortDetails: {
                port: "80",
                portName: "HTTP"
              },
              remoteIpDetails: {
                country: {
                  countryName: "Mexico"
                },
                city: {
                  cityName: "M?rida"
                },
                geoLocation: {
                  lon: "-89.616700",
                  lat: "20.950000"
                },
                organization: {
                  asnOrg: "Internet Mexico Company",
                  org: "Internet Mexico Company",
                  isp: "Internet Mexico Company",
                  asn: "4257"
                },
                ipAddressV4: "187.234.16.206"
              }
            }
          }
        },
        "serviceName": "guardduty"
      }
    }
  },
  rule: {
    firedtimes: 1,
    mail: false,
    level: 3,
    description: "AWS GuardDuty: PORT_PROBE - Unprotected port on EC2 instance {data.aws.resource.instanceDetails.instanceId} is being probed. [IP: {data.aws.service.action.portProbeAction.portProbeDetails.remoteIpDetails.ipAddressV4}] [Port: {data.aws.service.action.portProbeAction.portProbeDetails.localPortDetails.port}]",
    groups: ["amazon", "aws", "aws_guardduty"],
    id: "80305"
  },
  location: "Wazuh-AWS",
  decoder: {
    "name": "json"
  }
};
exports.guarddutyPortProbe = guarddutyPortProbe;
const apiCall = {
  "data": {
    "aws": {
      "severity": "5",
      "schemaVersion": "2.0",
      "resource": {
        "accessKeyDetails": {
          "principalId": "AIDAIL4SI43KE7QMMBABB",
          "userType": "IAMUser",
          "userName": ""
        },
        "resourceType": "AccessKey"
      },
      "log_info": {
        "s3bucket": "wazuh-aws-wodle",
        "log_file": "guardduty/2020/04/22/10/firehose_guardduty-1-2020-04-22-10-36-02-d67c99dc-800a-486a-8339-59a7a8254ab2.zip"
      },
      "description": "Unusual console login seen from principal {data.aws.resource.accessKeyDetails.userName}. Login activity using this client application, from the specific location has not been seen before from this principal.",
      "source": "guardduty",
      "type": "UnauthorizedAccess:IAMUser/ConsoleLogin",
      "title": "Unusual console login was seen for principal {data.aws.resource.accessKeyDetails.userName}.",
      "accountId": "166157447443",
      "createdAt": "2020-04-22T10:30:26.721Z",
      "partition": "aws",
      "service": {
        "archived": "false",
        "resourceRole": "TARGET",
        "detectorId": "cab38390b728c06fb2897dfcebffb80d",
        "eventFirstSeen": "2020-04-22T10:09:51Z",
        "eventLastSeen": "2020-04-22T10:09:55Z",
        "additionalInfo": {
          "recentApiCalls": {
            "count": "1",
            "api": "ConsoleLogin"
          }
        },
        "count": "1",
        "action": {
          "actionType": "AWS_API_CALL",
          "awsApiCallAction": {
            "callerType": "Remote IP",
            "api": "ConsoleLogin",
            "serviceName": "signin.amazonaws.com",
            "remoteIpDetails": {
              "country": {
                "countryName": "United States"
              },
              "city": {
                "cityName": "Ashburn"
              },
              "geoLocation": {
                "lon": "-77.472800",
                "lat": "39.048100"
              },
              "organization": {
                "asnOrg": "ASN-Internet-Com",
                "org": "Internet-Com",
                "isp": "Internet-Com",
                "asn": "27850"
              },
              "ipAddressV4": "80.14.0.90"
            }
          }
        },
        "serviceName": "guardduty"
      },
      "id": "a8b8d0b82c50eed686df4d24fa87b657",
      "region": "us-east-1",
      "arn": "arn:aws:guardduty:us-east-1:166157441478:detector/cab38390b728c06fb2897dfcebffc80d/finding/a8b8d0b82c50eed686df4d24fa87b657",
      "updatedAt": "2020-04-22T10:30:26.721Z"
    }
  },
  "rule": {
    // "firedtimes": 1,
    "mail": false,
    "level": 6,
    "description": "AWS GuardDuty: AWS_API_CALL - Unusual console login was seen for principal {data.aws.resource.accessKeyDetails.userName}.",
    "groups": ["amazon", "aws", "aws_guardduty"],
    "id": "80302"
  },
  "location": "Wazuh-AWS",
  "decoder": {
    "name": "json"
  }
};
exports.apiCall = apiCall;
const networkConnection = {
  "data": {
    "integration": "aws",
    "aws": {
      "severity": "5",
      "schemaVersion": "2.0",
      "resource": {
        "resourceType": "Instance"
      },
      "description": "EC2 instance {data.aws.resource.instanceDetails.instanceId} is communicating with a remote host on an unusual server port 5060.",
      "source": "guardduty",
      "type": "Behavior:EC2/NetworkPortUnusual",
      "title": "Unusual outbound communication seen from EC2 instance {data.aws.resource.instanceDetails.instanceId} on server port 5060.",
      "accountId": "166157441800",
      "createdAt": "2020-04-22T07:18:12.769Z",
      "partition": "aws",
      "service": {
        "archived": "false",
        "resourceRole": "ACTOR",
        "detectorId": "cab38390b728c06fb2897dfcebffc80d",
        "eventFirstSeen": "2020-04-22T07:13:44Z",
        "eventLastSeen": "2020-04-22T07:15:04Z",
        "additionalInfo": {
          "localPort": "50040",
          "outBytes": "1912",
          "inBytes": "4621",
          "unusual": "5060"
        },
        "count": "8",
        "action": {
          "actionType": "NETWORK_CONNECTION",
          "networkConnectionAction": {
            "localIpDetails": {
              "ipAddressV4": "10.0.0.251"
            },
            "protocol": "TCP",
            "blocked": "false",
            "connectionDirection": "OUTBOUND",
            "localPortDetails": {
              "port": "36220",
              "portName": "Unknown"
            },
            "remotePortDetails": {
              "port": "5050",
              "portName": "Unknown"
            },
            "remoteIpDetails": {
              "country": {
                "countryName": "United States"
              },
              "city": {
                "cityName": "Washington"
              },
              "geoLocation": {
                "lon": "-77.031900",
                "lat": "38.905700"
              },
              "organization": {
                "asnOrg": "ASN-Supreme-Web",
                "org": "Supreme Web",
                "isp": "Supreme Web",
                "asn": "395604"
              },
              "ipAddressV4": "8.2.14.2"
            }
          }
        },
        "serviceName": "guardduty"
      },
      "id": "06b8d0602d109db1282f9143809f80b8",
      "region": "us-east-1",
      "arn": "arn:aws:guardduty:{data.aws.region}:166157441758:detector/cab38390b728c06fb2897dfcebffb79d/finding/06b8d0602d109db1282f9143809f80b8",
      "updatedAt": "2020-04-22T07:18:12.778Z"
    }
  },
  "rule": {
    "mail": false,
    "level": 6,
    "description": "AWS GuardDuty: NETWORK_CONNECTION - Unusual outbound communication seen from EC2 instance {data.aws.resource.instanceDetails.instanceId} on server port 5060.",
    "groups": ["amazon", "aws", "aws_guardduty"],
    "id": "80302"
  },
  "location": "Wazuh-AWS",
  "decoder": {
    "name": "json"
  }
};
exports.networkConnection = networkConnection;
const iamPolicyGrantGlobal = {
  "data": {
    "aws": {
      "severity": "CRITICAL",
      "actor": "resources.wazuh.sample.com",
      "summary": {
        "Timestamps": "2020-04-22T00:11:44.617597Z,",
        "Description": "S3 Bucket uses IAM policy to grant read rights to Everyone. Your IAM policy contains a clause that effectively grants read access to any user. Please audit this bucket, and data contained within and confirm that this is intentional. If intentional, please use the alert whitelist feature to prevent future alerts",
        "Bucket": "resources.wazuh.sample.com,",
        "Record Count": "1",
        "Event Count": "1",
        "recipientAccountId": "166157441400",
        "ACL": {
          "resources": {
            "wazuh": {
              "com": {
                "Owner": {
                  "DisplayName": "wazuh",
                  "ID": "3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b48700"
                }
              }
            }
          }
        }
      },
      "risk-score": "9",
      "notification-type": "ALERT_CREATED",
      "name": "S3 Bucket IAM policy grants global read rights",
      "created-at": "2020-04-22T00:14:45.764008",
      "source": "macie",
      "url": "https://mt.{data.aws.region}.macie.aws.amazon.com/posts/arn%3Aaws%3Amacie%3A{data.aws.region}%3A166158075623%3Atrigger%2Fb731d9ffb1fe61508d4b490c92efa666%2Falert%2Fd78f0fd0a55ad458799e4c1fb6a0eded",
      "tags": {
        "value": "Open Permissions,Basic Alert,"
      },
      "alert-arn": "arn:aws:macie:{data.aws.region}:166157441400:trigger/b731d9ffb1fe61508d4a478c92efa666/alert/d78f0fd0a55ad458799e4c1fb6a0ed"
    }
  },
  "rule": {
    "mail": true,
    "level": 12,
    "description": "AWS Macie CRITICAL: S3 Bucket IAM policy grants global read rights - S3 Bucket uses IAM policy to grant read rights to Everyone. Your IAM policy contains a clause that effectively grants read access to any user. Please audit this bucket, and data contained within and confirm that this is intentional. If intentional, please use the alert whitelist feature to prevent future alerts",
    "groups": ["amazon", "aws", "aws_macie"],
    "id": "80355"
  },
  "location": "Wazuh-AWS",
  "decoder": {
    "name": "json"
  }
};
exports.iamPolicyGrantGlobal = iamPolicyGrantGlobal;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImF3cy5qcyJdLCJuYW1lcyI6WyJzb3VyY2UiLCJhY2NvdW50SWQiLCJyZWdpb24iLCJidWNrZXRzIiwiaW5zdGFuY2VJZCIsInJlbW90ZUlwRGV0YWlscyIsImNvdW50cnkiLCJjb3VudHJ5TmFtZSIsImNpdHkiLCJjaXR5TmFtZSIsImdlb0xvY2F0aW9uIiwibG9uIiwibGF0Iiwib3JnYW5pemF0aW9uIiwiYXNuT3JnIiwib3JnIiwiaXNwIiwiYXNuIiwiaXBBZGRyZXNzVjQiLCJpbnN0YW5jZURldGFpbHMiLCJndWFyZGR1dHlQb3J0UHJvYmUiLCJkYXRhIiwiYXdzIiwic2V2ZXJpdHkiLCJzY2hlbWFWZXJzaW9uIiwicmVzb3VyY2UiLCJyZXNvdXJjZVR5cGUiLCJkZXNjcmlwdGlvbiIsInR5cGUiLCJ0aXRsZSIsInBhcnRpdGlvbiIsInNlcnZpY2UiLCJhcmNoaXZlZCIsInJlc291cmNlUm9sZSIsImRldGVjdG9ySWQiLCJhZGRpdGlvbmFsSW5mbyIsInRocmVhdExpc3ROYW1lIiwidGhyZWF0TmFtZSIsImNvdW50IiwiYWN0aW9uIiwiYWN0aW9uVHlwZSIsInBvcnRQcm9iZUFjdGlvbiIsImJsb2NrZWQiLCJwb3J0UHJvYmVEZXRhaWxzIiwibG9jYWxQb3J0RGV0YWlscyIsInBvcnQiLCJwb3J0TmFtZSIsInJ1bGUiLCJmaXJlZHRpbWVzIiwibWFpbCIsImxldmVsIiwiZ3JvdXBzIiwiaWQiLCJsb2NhdGlvbiIsImRlY29kZXIiLCJhcGlDYWxsIiwibmV0d29ya0Nvbm5lY3Rpb24iLCJpYW1Qb2xpY3lHcmFudEdsb2JhbCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFFQztBQUNNLE1BQU1BLE1BQU0sR0FBRyxDQUFDLFdBQUQsRUFBYyxZQUFkLEVBQTRCLFNBQTVCLEVBQXVDLFFBQXZDLENBQWY7O0FBQ0EsTUFBTUMsU0FBUyxHQUFHLENBQUMsY0FBRCxF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QyxhQUFXO0FBQ1QsWUFBUTtBQURDO0FBN0N1QixDQUE3QiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBBV1Mgc2FtcGxlIGRhdGFcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5cbiAvLyBBbWF6b24gQVdTIHNlcnZpY2VzXG5leHBvcnQgY29uc3Qgc291cmNlID0gW1wiZ3VhcmRkdXR5XCIsIFwiY2xvdWR0cmFpbFwiLCBcInZwY2Zsb3dcIiwgXCJjb25maWdcIl07XG5leHBvcnQgY29uc3QgYWNjb3VudElkID0gW1wiMTg2MTU3NTAxNjI0XCIsIFwiMTE3NTIxMjM1MzgyXCIsIFwiMTUwNDQ3MTI1MjAxXCIsIFwiMTg3NzM0NTU2NDBcIiwgXCIxODYxNTQxNzE3ODBcIiwgXCIyNTAxNDE3MDEwMTVcIl07XG5leHBvcnQgY29uc3QgcmVnaW9uID0gW1wiZXUtd2VzdC0xXCIsIFwiZXUtd2VzdC0yXCIsIFwiZXUtd2VzdC0zXCIsIFwiZXUtbm9ydGgtMVwiLCBcImV1LWNlbnRyYWwtMVwiLCBcInVzLWVhc3QtMVwiLCBcInVzLWVhc3QtMlwiLCBcInVzLXdlc3QtMVwiLCBcInVzLXdlc3QtMlwiLCBcIm1lLXNvdXRoLTFcIiwgXCJhcC1lYXN0LTFcIiwgXCJhcC1lYXN0LTJcIiwgXCJhcC1ub3J0aGVhc3QtMlwiLCBcImFwLW5vcnRoZWFzdC0zXCIsIFwiYXAtc291dGgtMVwiLCBcImFwLXNvdXRoZWFzdC0xXCIsIFwiYXAtc291dGhlYXN0LTJcIiwgXCJhcC1ub3J0aGVhc3QtMVwiLCBcImNhLWNlbnRyYWwtMVwiXTsgLy8gaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL2VzX2VzL0FXU0VDMi9sYXRlc3QvVXNlckd1aWRlL3VzaW5nLXJlZ2lvbnMtYXZhaWxhYmlsaXR5LXpvbmVzLmh0bWwjY29uY2VwdHMtcmVnaW9uc1xuZXhwb3J0IGNvbnN0IGJ1Y2tldHMgPSBbXCJhd3Mtc2FtcGxlLWJ1Y2tldC0xXCIsIFwiYXdzLXNhbXBsZS1idWNrZXQtMlwiLCBcImF3cy1zYW1wbGUtYnVja2V0LTNcIiwgXCJhd3Mtc2FtcGxlLWJ1Y2tldC00XCIsIFwiYXdzLXNhbXBsZS1idWNrZXQtNVwiLCBcImF3cy1zYW1wbGUtYnVja2V0LTZcIiwgXCJhd3Mtc2FtcGxlLWJ1Y2tldC03XCIsIFwiYXdzLXNhbXBsZS1idWNrZXQtOFwiLCBcImF3cy1zYW1wbGUtYnVja2V0LTlcIl07XG5cbmV4cG9ydCBjb25zdCBpbnN0YW5jZUlkID0gWydpLTA2MGJiMDE2OTlkZGRjMjBjJywnaS0wNjBiYjAyMDQ3OWJlZGMyMHcnLCAnaS0wNzBlYjAyMDQ3OWJlYmYyMGEnLCAnaS0wNzBlYjAxNTQ3OWJlZmIxNWQnLCAnaS0wNTdlYjA2MDc3OWZkYWUxNWInXTtcblxuZXhwb3J0IGNvbnN0IHJlbW90ZUlwRGV0YWlscyA9IFtcbiAge1xuICAgIGNvdW50cnk6IHtcbiAgICAgIGNvdW50cnlOYW1lOiBcIk1leGljb1wiXG4gICAgfSxcbiAgICBjaXR5OiB7XG4gICAgICBjaXR5TmFtZTogXCJNw6lyaWRhXCJcbiAgICB9LFxuICAgIGdlb0xvY2F0aW9uOiB7XG4gICAgICBsb246IFwiLTg5LjYxNjcwMFwiLFxuICAgICAgbGF0OiBcIjIwLjk1MDAwMFwiXG4gICAgfSxcbiAgICBvcmdhbml6YXRpb246IHtcbiAgICAgIGFzbk9yZzogXCJJbnRlcm5ldCBNZXhpY28gQ29tcGFueVwiLFxuICAgICAgb3JnOiBcIkludGVybmV0IE1leGljbyBDb21wYW55XCIsXG4gICAgICBpc3A6IFwiSW50ZXJuZXQgTWV4aWNvIENvbXBhbnlcIixcbiAgICAgIGFzbjogXCI0MjU3XCJcbiAgICB9LFxuICAgIGlwQWRkcmVzc1Y0OiBcIjE2MC4wLjE0LjQwXCJcbiAgfSxcbiAge1xuICAgIGNvdW50cnk6IHtcbiAgICAgIGNvdW50cnlOYW1lOiBcIkl0YWx5XCJcbiAgICB9LFxuICAgIGNpdHk6IHtcbiAgICAgIGNpdHlOYW1lOiBcIlNhdm9uYVwiXG4gICAgfSxcbiAgICBnZW9Mb2NhdGlvbjoge1xuICAgICAgbG9uOiBcIjguNDc3MjAwXCIsXG4gICAgICBsYXQ6IFwiNDQuMzA5MDAwXCJcbiAgICB9LFxuICAgIG9yZ2FuaXphdGlvbjoge1xuICAgICAgYXNuT3JnOiBcIlNwZWVkd2ViXCIsXG4gICAgICBvcmc6IFwiU3BlZWR3ZWJcIixcbiAgICAgIGlzcDogXCJTcGVlZHdlYlwiLFxuICAgICAgYXNuOiBcIjQyNzg0XCJcbiAgICB9LFxuICAgIGlwQWRkcmVzc1Y0OiBcIjIuMjUuODAuNDVcIlxuICB9LFxuICB7XG4gICAgY291bnRyeToge1xuICAgICAgY291bnRyeU5hbWU6IFwiTWV4aWNvXCJcbiAgICB9LFxuICAgIGNpdHk6IHtcbiAgICAgIGNpdHlOYW1lOiBcIkNvbGltYVwiXG4gICAgfSxcbiAgICBnZW9Mb2NhdGlvbjoge1xuICAgICAgbG9uOiBcIi0xMDMuNzE0NTAwXCIsXG4gICAgICBsYXQ6IFwiMTkuMjY2ODAwXCJcbiAgICB9LFxuICAgIG9yZ2FuaXphdGlvbjoge1xuICAgICAgYXNuT3JnOiBcIkludGVybmV0IE1leGljbyBDb21wYW55XCIsXG4gICAgICBvcmc6IFwiSW50ZXJuZXQgTWV4aWNvIENvbXBhbnlcIixcbiAgICAgIGlzcDogXCJJbnRlcm5ldCBNZXhpY28gQ29tcGFueVwiLFxuICAgICAgYXNuOiBcIjQyNTdcIlxuICAgIH0sXG4gICAgaXBBZGRyZXNzVjQ6IFwiMTg3LjIzNC4xNi4yMDZcIlxuICB9LFxuICB7XG4gICAgY291bnRyeToge1xuICAgICAgY291bnRyeU5hbWU6IFwiTmV0aGVybGFuZHNcIlxuICAgIH0sXG4gICAgY2l0eToge1xuICAgICAgY2l0eU5hbWU6IFwiQW1zdGVyZGFtXCJcbiAgICB9LFxuICAgIGdlb0xvY2F0aW9uOiB7XG4gICAgICBsb246IFwiNC44ODk3MDBcIixcbiAgICAgIGxhdDogXCI1Mi4zNzQwMDBcIlxuICAgIH0sXG4gICAgb3JnYW5pemF0aW9uOiB7XG4gICAgICBhc25Pcmc6IFwiTmV0aGVybGFuZHMgVGVsZWNvbVwiLFxuICAgICAgb3JnOiBcIk5ldGhlcmxhbmRzIFRlbGVjb21cIixcbiAgICAgIGlzcDogXCJOZXRoZXJsYW5kcyBUZWxlY29tXCIsXG4gICAgICBhc246IFwiNDAwNzBcIlxuICAgIH0sXG4gICAgaXBBZGRyZXNzVjQ6IFwiMTYwLjAuMTQuNDBcIlxuICB9LFxuICB7XG4gICAgY291bnRyeToge1xuICAgICAgXCJjb3VudHJ5TmFtZVwiOiBcIkl0YWx5XCJcbiAgICB9LFxuICAgIGNpdHk6IHtcbiAgICAgIGNpdHlOYW1lOiBcIlBhbGVybW9cIlxuICAgIH0sXG4gICAgZ2VvTG9jYXRpb246IHtcbiAgICAgIGxvbjogXCIxMy4zMzQxMDBcIixcbiAgICAgIGxhdDogXCIzOC4xMjkwMDBcIlxuICAgIH0sXG4gICAgb3JnYW5pemF0aW9uOiB7XG4gICAgICBhc25Pcmc6IFwiTmV0IENvbm5lY3Rpb25zXCIsXG4gICAgICBvcmc6IFwiTmV0IENvbm5lY3Rpb25zXCIsXG4gICAgICBpc3A6IFwiTmV0IENvbm5lY3Rpb25zXCIsXG4gICAgICBhc246IFwiMTU0N1wiXG4gICAgfSxcbiAgICBpcEFkZHJlc3NWNDogXCI3NS4wLjEwMS4yNDVcIlxuICB9LFxuICB7XG4gICAgY291bnRyeToge1xuICAgICAgY291bnRyeU5hbWU6IFwiVW5pdGVkIFN0YXRlc1wiXG4gICAgfSxcbiAgICBjaXR5OiB7XG4gICAgICBjaXR5TmFtZTogXCJQYW5hbWEgQ2l0eVwiXG4gICAgfSxcbiAgICBnZW9Mb2NhdGlvbjoge1xuICAgICAgbG9uOiBcIi04NS42Njk2MDBcIixcbiAgICAgIGxhdDogXCIzMC4xOTA5MDBcIlxuICAgIH0sXG4gICAgb3JnYW5pemF0aW9uOiB7XG4gICAgICBhc25Pcmc6IFwiSW50ZXJuZXQgSW5ub3ZhdGlvbnNcIixcbiAgICAgIG9yZzogXCJJbnRlbmV0IElubm92YXRpb25zXCIsXG4gICAgICBpc3A6IFwiSW50ZW5ldCBJbm5vdmF0aW9uc1wiLFxuICAgICAgYXNuOiBcIjQyNTJcIlxuICAgIH0sXG4gICAgaXBBZGRyZXNzVjQ6IFwiNzAuMjQuMTAxLjIxNFwiXG4gIH1cbl07XG5cbmV4cG9ydCBjb25zdCBpbnN0YW5jZURldGFpbHMgPSBbXG4gIHtcbiAgICBcImxhdW5jaFRpbWVcIjogXCIyMDIwLTA0LTIyVDExOjE3OjA4WlwiLFxuICAgIFwiaW5zdGFuY2VJZFwiOiBcImktMGIwYjhiMzRhNDhjOGYxYzRcIixcbiAgICBcIm5ldHdvcmtJbnRlcmZhY2VzXCI6IHtcbiAgICAgIFwibmV0d29ya0ludGVyZmFjZUlkXCI6IFwiZW5pLTAxZTc3N2ZiOWFjZDU0OGU0XCIsXG4gICAgICBcInN1Ym5ldElkXCI6IFwic3VibmV0LTc5MzBkYTIyXCIsXG4gICAgICBcInZwY0lkXCI6IFwidnBjLTY4ZTNjNjBmXCIsXG4gICAgICBcInByaXZhdGVEbnNOYW1lXCI6IFwiaXAtMTAtMC0yLTIuZWMyLmludGVybmFsXCIsXG4gICAgICBcInB1YmxpY0lwXCI6IFwiNDAuMjIwLjEyNS4yMDRcIixcbiAgICAgIFwicHVibGljRG5zTmFtZVwiOiBcImVjMi00MC4yMjAuMTI1LjIwNC5jb21wdXRlLTEuYW1hem9uYXdzLmNvbVwiLFxuICAgICAgXCJwcml2YXRlSXBBZGRyZXNzXCI6IFwiMTAuMC4yLjJcIlxuICAgIH0sXG4gICAgXCJpbnN0YW5jZVN0YXRlXCI6IFwicnVubmluZ1wiLFxuICAgIFwiaW1hZ2VJZFwiOiBcImFtaS0wZmY4YTkxNTA3Zjc3ZjkwMFwiLFxuICAgIFwiaW5zdGFuY2VUeXBlXCI6IFwidDIuc21hbGxcIixcbiAgICBcImltYWdlRGVzY3JpcHRpb25cIjogXCJBbWF6b24gTGludXggQU1JIDIwMTguMDMuMC4yMDE4MDgxMSB4ODZfNjQgSFZNIEdQMlwiLFxuICAgIFwiaWFtSW5zdGFuY2VQcm9maWxlXCI6IHtcbiAgICAgIFwiaWRcIjogXCJBSVBBSkdBWk1GUFpIS0lCT0NCSUdcIixcbiAgICAgIFwiYXJuXCI6IFwiYXJuOmF3czppYW06OntkYXRhLmF3cy5hY2NvdW50SWR9Omluc3RhbmNlLXByb2ZpbGUvb3Bzd29ya3Mtd2ViLXByb2R1Y3Rpb25cIlxuICAgIH0sXG4gICAgXCJhdmFpbGFiaWxpdHlab25lXCI6IFwidXMtZWFzdC0xYVwiXG4gIH0sXG4gIHtcbiAgICBcImxhdW5jaFRpbWVcIjogXCIyMDE5LTAzLTIyVDE0OjE1OjQxWlwiLFxuICAgIFwiaW5zdGFuY2VJZFwiOiBcImktMGNhYjRhMDgzZDU3ZGM0MDBcIixcbiAgICBcIm5ldHdvcmtJbnRlcmZhY2VzXCI6IHtcbiAgICAgIFwibmV0d29ya0ludGVyZmFjZUlkXCI6IFwiZW5pLTBiYjQ2NWIyZDkzOWRiZGE2XCIsXG4gICAgICBcInN1Ym5ldElkXCI6IFwic3VibmV0LTZiMWQ2MjAzXCIsXG4gICAgICBcInZwY0lkXCI6IFwidnBjLTkyMWU2MWZhXCIsXG4gICAgICBcInByaXZhdGVEbnNOYW1lXCI6IFwiaXAtMTAtMC0wLTEuZWMyLmludGVybmFsXCIsXG4gICAgICBcInB1YmxpY0lwXCI6IFwiNTQuOTAuNDguMzhcIixcbiAgICAgIFwicHVibGljRG5zTmFtZVwiOiBcImVjMi01NC45MC40OC4zOC5jb21wdXRlLTEuYW1hem9uYXdzLmNvbVwiLFxuICAgICAgXCJwcml2YXRlSXBBZGRyZXNzXCI6IFwiMTAuMC4wLjFcIlxuICAgIH0sXG4gICAgXCJpbnN0YW5jZVN0YXRlXCI6IFwicnVubmluZ1wiLFxuICAgIFwiaW1hZ2VJZFwiOiBcImFtaS0wOWFlNjdiYmZjZDc0MDg3NVwiLFxuICAgIFwiaW5zdGFuY2VUeXBlXCI6IFwiYTEubWVkaXVtXCIsXG4gICAgXCJpbWFnZURlc2NyaXB0aW9uXCI6IFwiQ2Fub25pY2FsLCBVYnVudHUsIDE4LjA0IExUUywgVU5TVVBQT1JURUQgZGFpbHkgYXJtNjQgYmlvbmljIGltYWdlIGJ1aWxkIG9uIDIwMTktMDItMTJcIixcbiAgICBcInByb2R1Y3RDb2Rlc1wiOiB7XG4gICAgICBcInByb2R1Y3RDb2RlSWRcIjogXCJ6dWQxdTRram14dTJqMmpmMG4zNmJxYVwiLFxuICAgICAgXCJwcm9kdWN0Q29kZVR5cGVcIjogXCJtYXJrZXRwbGFjZVwiXG4gICAgfSxcbiAgICBcImlhbUluc3RhbmNlUHJvZmlsZVwiOiB7IC8vIEZJWE1FXG4gICAgICBcImlkXCI6IFwiQUlQQUpHQVpNRlBaSEtJQk9VRkdBXCIsXG4gICAgICBcImFyblwiOiBcImFybjphd3M6aWFtOjp7ZGF0YS5hd3MuYWNjb3VudElkfTppbnN0YW5jZS1wcm9maWxlL29wc3dvcmtzLXdlYi1wcm9kdWN0aW9uXCJcbiAgICB9LFxuICAgIFwiYXZhaWxhYmlsaXR5Wm9uZVwiOiBcInVzLWVhc3QtMWVcIlxuICB9XG5dXG5cbmV4cG9ydCBjb25zdCBndWFyZGR1dHlQb3J0UHJvYmUgPSB7XG4gIGRhdGE6IHtcbiAgICBhd3M6IHtcbiAgICAgIHNldmVyaXR5OiBcIjJcIixcbiAgICAgIHNjaGVtYVZlcnNpb246IFwiMi4wXCIsXG4gICAgICByZXNvdXJjZToge1xuICAgICAgICAvLyBpbnN0YW5jZURldGFpbHNcbiAgICAgICAgcmVzb3VyY2VUeXBlOiBcIkluc3RhbmNlXCJcbiAgICAgIH0sXG4gICAgICBkZXNjcmlwdGlvbjogXCJFQzIgaW5zdGFuY2UgaGFzIGFuIHVucHJvdGVjdGVkIHBvcnQgd2hpY2ggaXMgYmVpbmcgcHJvYmVkIGJ5IGEga25vd24gbWFsaWNpb3VzIGhvc3QuXCIsXG4gICAgICBzb3VyY2U6IFwiZ3VhcmRkdXR5XCIsXG4gICAgICB0eXBlOiBcIlJlY29uOkVDMi9Qb3J0UHJvYmVVbnByb3RlY3RlZFBvcnRcIixcbiAgICAgIHRpdGxlOiBcIlVucHJvdGVjdGVkIHBvcnQgb24gRUMyIGluc3RhbmNlIHtkYXRhLmF3cy5yZXNvdXJjZS5pbnN0YW5jZURldGFpbHMuaW5zdGFuY2VJZH0gaXMgYmVpbmcgcHJvYmVkLlwiLFxuICAgICAgLy8gYWNjb3VudElkOiBcIjE2NjE1NzQ0MTYyM1wiLFxuICAgICAgLy8gY3JlYXRlZEF0OiBcIjIwMTktMDctMzFUMTY6MzE6MTQuNzM5WlwiLFxuICAgICAgcGFydGl0aW9uOiBcImF3c1wiLFxuICAgICAgc2VydmljZToge1xuICAgICAgICBhcmNoaXZlZDogXCJmYWxzZVwiLFxuICAgICAgICByZXNvdXJjZVJvbGU6IFwiVEFSR0VUXCIsXG4gICAgICAgIGRldGVjdG9ySWQ6IFwiY2FiMzgzOTBiNDAwYzA2ZmIyODk3ZGZjZWJmZmI4MGRcIixcbiAgICAgICAgLy8gZXZlbnRGaXJzdFNlZW46IFwiMjAxOS0wNy0zMVQxNjoxODowOFpcIixcbiAgICAgICAgLy8gZXZlbnRMYXN0U2VlbjogXCIyMDIwLTA0LTIyVDA0OjExOjAxWlwiLFxuICAgICAgICBhZGRpdGlvbmFsSW5mbzoge1xuICAgICAgICAgIHRocmVhdExpc3ROYW1lOiBcIlByb29mUG9pbnRcIixcbiAgICAgICAgICB0aHJlYXROYW1lOiBcIlNjYW5uZXJcIlxuICAgICAgICB9LFxuICAgICAgICBjb3VudDogXCIyNTk0XCIsXG4gICAgICAgIGFjdGlvbjoge1xuICAgICAgICAgIGFjdGlvblR5cGU6IFwiUE9SVF9QUk9CRVwiLFxuICAgICAgICAgIHBvcnRQcm9iZUFjdGlvbjoge1xuICAgICAgICAgICAgYmxvY2tlZDogXCJmYWxzZVwiLFxuICAgICAgICAgICAgcG9ydFByb2JlRGV0YWlsczoge1xuICAgICAgICAgICAgICBsb2NhbFBvcnREZXRhaWxzOiB7XG4gICAgICAgICAgICAgICAgcG9ydDogXCI4MFwiLFxuICAgICAgICAgICAgICAgIHBvcnROYW1lOiBcIkhUVFBcIlxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICByZW1vdGVJcERldGFpbHM6IHtcbiAgICAgICAgICAgICAgICBjb3VudHJ5OiB7XG4gICAgICAgICAgICAgICAgICBjb3VudHJ5TmFtZTogXCJNZXhpY29cIlxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgY2l0eToge1xuICAgICAgICAgICAgICAgICAgY2l0eU5hbWU6IFwiTT9yaWRhXCJcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIGdlb0xvY2F0aW9uOiB7XG4gICAgICAgICAgICAgICAgICBsb246IFwiLTg5LjYxNjcwMFwiLFxuICAgICAgICAgICAgICAgICAgbGF0OiBcIjIwLjk1MDAwMFwiXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBvcmdhbml6YXRpb246IHtcbiAgICAgICAgICAgICAgICAgIGFzbk9yZzogXCJJbnRlcm5ldCBNZXhpY28gQ29tcGFueVwiLFxuICAgICAgICAgICAgICAgICAgb3JnOiBcIkludGVybmV0IE1leGljbyBDb21wYW55XCIsXG4gICAgICAgICAgICAgICAgICBpc3A6IFwiSW50ZXJuZXQgTWV4aWNvIENvbXBhbnlcIixcbiAgICAgICAgICAgICAgICAgIGFzbjogXCI0MjU3XCJcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIGlwQWRkcmVzc1Y0OiBcIjE4Ny4yMzQuMTYuMjA2XCJcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgXCJzZXJ2aWNlTmFtZVwiOiBcImd1YXJkZHV0eVwiXG4gICAgICB9XG4gICAgfVxuICB9LFxuICBydWxlOiB7XG4gICAgZmlyZWR0aW1lczogMSxcbiAgICBtYWlsOiBmYWxzZSxcbiAgICBsZXZlbDogMyxcbiAgICBkZXNjcmlwdGlvbjogXCJBV1MgR3VhcmREdXR5OiBQT1JUX1BST0JFIC0gVW5wcm90ZWN0ZWQgcG9ydCBvbiBFQzIgaW5zdGFuY2Uge2RhdGEuYXdzLnJlc291cmNlLmluc3RhbmNlRGV0YWlscy5pbnN0YW5jZUlkfSBpcyBiZWluZyBwcm9iZWQuIFtJUDoge2RhdGEuYXdzLnNlcnZpY2UuYWN0aW9uLnBvcnRQcm9iZUFjdGlvbi5wb3J0UHJvYmVEZXRhaWxzLnJlbW90ZUlwRGV0YWlscy5pcEFkZHJlc3NWNH1dIFtQb3J0OiB7ZGF0YS5hd3Muc2VydmljZS5hY3Rpb24ucG9ydFByb2JlQWN0aW9uLnBvcnRQcm9iZURldGFpbHMubG9jYWxQb3J0RGV0YWlscy5wb3J0fV1cIixcbiAgICBncm91cHM6IFtcImFtYXpvblwiLFwiYXdzXCIsXCJhd3NfZ3VhcmRkdXR5XCJdLFxuICAgIGlkOiBcIjgwMzA1XCJcbiAgfSxcbiAgbG9jYXRpb246IFwiV2F6dWgtQVdTXCIsXG4gIGRlY29kZXI6IHtcbiAgICBcIm5hbWVcIjogXCJqc29uXCJcbiAgfSxcbn07XG5cbmV4cG9ydCBjb25zdCBhcGlDYWxsID0ge1xuICBcImRhdGFcIjoge1xuICAgIFwiYXdzXCI6IHtcbiAgICAgIFwic2V2ZXJpdHlcIjogXCI1XCIsXG4gICAgICBcInNjaGVtYVZlcnNpb25cIjogXCIyLjBcIixcbiAgICAgIFwicmVzb3VyY2VcIjoge1xuICAgICAgICBcImFjY2Vzc0tleURldGFpbHNcIjoge1xuICAgICAgICAgIFwicHJpbmNpcGFsSWRcIjogXCJBSURBSUw0U0k0M0tFN1FNTUJBQkJcIixcbiAgICAgICAgICBcInVzZXJUeXBlXCI6IFwiSUFNVXNlclwiLFxuICAgICAgICAgIFwidXNlck5hbWVcIjogXCJcIlxuICAgICAgICB9LFxuICAgICAgICBcInJlc291cmNlVHlwZVwiOiBcIkFjY2Vzc0tleVwiXG4gICAgICB9LFxuICAgICAgXCJsb2dfaW5mb1wiOiB7XG4gICAgICAgIFwiczNidWNrZXRcIjogXCJ3YXp1aC1hd3Mtd29kbGVcIixcbiAgICAgICAgXCJsb2dfZmlsZVwiOiBcImd1YXJkZHV0eS8yMDIwLzA0LzIyLzEwL2ZpcmVob3NlX2d1YXJkZHV0eS0xLTIwMjAtMDQtMjItMTAtMzYtMDItZDY3Yzk5ZGMtODAwYS00ODZhLTgzMzktNTlhN2E4MjU0YWIyLnppcFwiXG4gICAgICB9LFxuICAgICAgXCJkZXNjcmlwdGlvblwiOiBcIlVudXN1YWwgY29uc29sZSBsb2dpbiBzZWVuIGZyb20gcHJpbmNpcGFsIHtkYXRhLmF3cy5yZXNvdXJjZS5hY2Nlc3NLZXlEZXRhaWxzLnVzZXJOYW1lfS4gTG9naW4gYWN0aXZpdHkgdXNpbmcgdGhpcyBjbGllbnQgYXBwbGljYXRpb24sIGZyb20gdGhlIHNwZWNpZmljIGxvY2F0aW9uIGhhcyBub3QgYmVlbiBzZWVuIGJlZm9yZSBmcm9tIHRoaXMgcHJpbmNpcGFsLlwiLFxuICAgICAgXCJzb3VyY2VcIjogXCJndWFyZGR1dHlcIixcbiAgICAgIFwidHlwZVwiOiBcIlVuYXV0aG9yaXplZEFjY2VzczpJQU1Vc2VyL0NvbnNvbGVMb2dpblwiLFxuICAgICAgXCJ0aXRsZVwiOiBcIlVudXN1YWwgY29uc29sZSBsb2dpbiB3YXMgc2VlbiBmb3IgcHJpbmNpcGFsIHtkYXRhLmF3cy5yZXNvdXJjZS5hY2Nlc3NLZXlEZXRhaWxzLnVzZXJOYW1lfS5cIixcbiAgICAgIFwiYWNjb3VudElkXCI6IFwiMTY2MTU3NDQ3NDQzXCIsXG4gICAgICBcImNyZWF0ZWRBdFwiOiBcIjIwMjAtMDQtMjJUMTA6MzA6MjYuNzIxWlwiLFxuICAgICAgXCJwYXJ0aXRpb25cIjogXCJhd3NcIixcbiAgICAgIFwic2VydmljZVwiOiB7XG4gICAgICAgIFwiYXJjaGl2ZWRcIjogXCJmYWxzZVwiLFxuICAgICAgICBcInJlc291cmNlUm9sZVwiOiBcIlRBUkdFVFwiLFxuICAgICAgICBcImRldGVjdG9ySWRcIjogXCJjYWIzODM5MGI3MjhjMDZmYjI4OTdkZmNlYmZmYjgwZFwiLFxuICAgICAgICBcImV2ZW50Rmlyc3RTZWVuXCI6IFwiMjAyMC0wNC0yMlQxMDowOTo1MVpcIixcbiAgICAgICAgXCJldmVudExhc3RTZWVuXCI6IFwiMjAyMC0wNC0yMlQxMDowOTo1NVpcIixcbiAgICAgICAgXCJhZGRpdGlvbmFsSW5mb1wiOiB7XG4gICAgICAgICAgXCJyZWNlbnRBcGlDYWxsc1wiOiB7XG4gICAgICAgICAgICBcImNvdW50XCI6IFwiMVwiLFxuICAgICAgICAgICAgXCJhcGlcIjogXCJDb25zb2xlTG9naW5cIlxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgXCJjb3VudFwiOiBcIjFcIixcbiAgICAgICAgXCJhY3Rpb25cIjoge1xuICAgICAgICAgIFwiYWN0aW9uVHlwZVwiOiBcIkFXU19BUElfQ0FMTFwiLFxuICAgICAgICAgIFwiYXdzQXBpQ2FsbEFjdGlvblwiOiB7XG4gICAgICAgICAgICBcImNhbGxlclR5cGVcIjogXCJSZW1vdGUgSVBcIixcbiAgICAgICAgICAgIFwiYXBpXCI6IFwiQ29uc29sZUxvZ2luXCIsXG4gICAgICAgICAgICBcInNlcnZpY2VOYW1lXCI6IFwic2lnbmluLmFtYXpvbmF3cy5jb21cIixcbiAgICAgICAgICAgIFwicmVtb3RlSXBEZXRhaWxzXCI6IHtcbiAgICAgICAgICAgICAgXCJjb3VudHJ5XCI6IHtcbiAgICAgICAgICAgICAgICBcImNvdW50cnlOYW1lXCI6IFwiVW5pdGVkIFN0YXRlc1wiXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIFwiY2l0eVwiOiB7XG4gICAgICAgICAgICAgICAgXCJjaXR5TmFtZVwiOiBcIkFzaGJ1cm5cIlxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBcImdlb0xvY2F0aW9uXCI6IHtcbiAgICAgICAgICAgICAgICBcImxvblwiOiBcIi03Ny40NzI4MDBcIixcbiAgICAgICAgICAgICAgICBcImxhdFwiOiBcIjM5LjA0ODEwMFwiXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIFwib3JnYW5pemF0aW9uXCI6IHtcbiAgICAgICAgICAgICAgICBcImFzbk9yZ1wiOiBcIkFTTi1JbnRlcm5ldC1Db21cIixcbiAgICAgICAgICAgICAgICBcIm9yZ1wiOiBcIkludGVybmV0LUNvbVwiLFxuICAgICAgICAgICAgICAgIFwiaXNwXCI6IFwiSW50ZXJuZXQtQ29tXCIsXG4gICAgICAgICAgICAgICAgXCJhc25cIjogXCIyNzg1MFwiXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIFwiaXBBZGRyZXNzVjRcIjogXCI4MC4xNC4wLjkwXCJcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIFwic2VydmljZU5hbWVcIjogXCJndWFyZGR1dHlcIlxuICAgICAgfSxcbiAgICAgIFwiaWRcIjogXCJhOGI4ZDBiODJjNTBlZWQ2ODZkZjRkMjRmYTg3YjY1N1wiLFxuICAgICAgXCJyZWdpb25cIjogXCJ1cy1lYXN0LTFcIixcbiAgICAgIFwiYXJuXCI6IFwiYXJuOmF3czpndWFyZGR1dHk6dXMtZWFzdC0xOjE2NjE1NzQ0MTQ3ODpkZXRlY3Rvci9jYWIzODM5MGI3MjhjMDZmYjI4OTdkZmNlYmZmYzgwZC9maW5kaW5nL2E4YjhkMGI4MmM1MGVlZDY4NmRmNGQyNGZhODdiNjU3XCIsXG4gICAgICBcInVwZGF0ZWRBdFwiOiBcIjIwMjAtMDQtMjJUMTA6MzA6MjYuNzIxWlwiXG4gICAgfVxuICB9LFxuICBcInJ1bGVcIjoge1xuICAgIC8vIFwiZmlyZWR0aW1lc1wiOiAxLFxuICAgIFwibWFpbFwiOiBmYWxzZSxcbiAgICBcImxldmVsXCI6IDYsXG4gICAgXCJkZXNjcmlwdGlvblwiOiBcIkFXUyBHdWFyZER1dHk6IEFXU19BUElfQ0FMTCAtIFVudXN1YWwgY29uc29sZSBsb2dpbiB3YXMgc2VlbiBmb3IgcHJpbmNpcGFsIHtkYXRhLmF3cy5yZXNvdXJjZS5hY2Nlc3NLZXlEZXRhaWxzLnVzZXJOYW1lfS5cIixcbiAgICBcImdyb3Vwc1wiOiBbXG4gICAgICBcImFtYXpvblwiLFxuICAgICAgXCJhd3NcIixcbiAgICAgIFwiYXdzX2d1YXJkZHV0eVwiXG4gICAgXSxcbiAgICBcImlkXCI6IFwiODAzMDJcIlxuICB9LFxuICBcImxvY2F0aW9uXCI6IFwiV2F6dWgtQVdTXCIsXG4gIFwiZGVjb2RlclwiOiB7XG4gICAgXCJuYW1lXCI6IFwianNvblwiXG4gIH1cbn07XG5cbmV4cG9ydCBjb25zdCBuZXR3b3JrQ29ubmVjdGlvbiA9IHtcbiAgXCJkYXRhXCI6IHtcbiAgICBcImludGVncmF0aW9uXCI6IFwiYXdzXCIsXG4gICAgXCJhd3NcIjoge1xuICAgICAgXCJzZXZlcml0eVwiOiBcIjVcIixcbiAgICAgIFwic2NoZW1hVmVyc2lvblwiOiBcIjIuMFwiLFxuICAgICAgXCJyZXNvdXJjZVwiOiB7XG4gICAgICAgIFwicmVzb3VyY2VUeXBlXCI6IFwiSW5zdGFuY2VcIlxuICAgICAgfSxcbiAgICAgIFwiZGVzY3JpcHRpb25cIjogXCJFQzIgaW5zdGFuY2Uge2RhdGEuYXdzLnJlc291cmNlLmluc3RhbmNlRGV0YWlscy5pbnN0YW5jZUlkfSBpcyBjb21tdW5pY2F0aW5nIHdpdGggYSByZW1vdGUgaG9zdCBvbiBhbiB1bnVzdWFsIHNlcnZlciBwb3J0IDUwNjAuXCIsXG4gICAgICBcInNvdXJjZVwiOiBcImd1YXJkZHV0eVwiLFxuICAgICAgXCJ0eXBlXCI6IFwiQmVoYXZpb3I6RUMyL05ldHdvcmtQb3J0VW51c3VhbFwiLFxuICAgICAgXCJ0aXRsZVwiOiBcIlVudXN1YWwgb3V0Ym91bmQgY29tbXVuaWNhdGlvbiBzZWVuIGZyb20gRUMyIGluc3RhbmNlIHtkYXRhLmF3cy5yZXNvdXJjZS5pbnN0YW5jZURldGFpbHMuaW5zdGFuY2VJZH0gb24gc2VydmVyIHBvcnQgNTA2MC5cIixcbiAgICAgIFwiYWNjb3VudElkXCI6IFwiMTY2MTU3NDQxODAwXCIsXG4gICAgICBcImNyZWF0ZWRBdFwiOiBcIjIwMjAtMDQtMjJUMDc6MTg6MTIuNzY5WlwiLFxuICAgICAgXCJwYXJ0aXRpb25cIjogXCJhd3NcIixcbiAgICAgIFwic2VydmljZVwiOiB7XG4gICAgICAgIFwiYXJjaGl2ZWRcIjogXCJmYWxzZVwiLFxuICAgICAgICBcInJlc291cmNlUm9sZVwiOiBcIkFDVE9SXCIsXG4gICAgICAgIFwiZGV0ZWN0b3JJZFwiOiBcImNhYjM4MzkwYjcyOGMwNmZiMjg5N2RmY2ViZmZjODBkXCIsXG4gICAgICAgIFwiZXZlbnRGaXJzdFNlZW5cIjogXCIyMDIwLTA0LTIyVDA3OjEzOjQ0WlwiLFxuICAgICAgICBcImV2ZW50TGFzdFNlZW5cIjogXCIyMDIwLTA0LTIyVDA3OjE1OjA0WlwiLFxuICAgICAgICBcImFkZGl0aW9uYWxJbmZvXCI6IHtcbiAgICAgICAgICBcImxvY2FsUG9ydFwiOiBcIjUwMDQwXCIsXG4gICAgICAgICAgXCJvdXRCeXRlc1wiOiBcIjE5MTJcIixcbiAgICAgICAgICBcImluQnl0ZXNcIjogXCI0NjIxXCIsXG4gICAgICAgICAgXCJ1bnVzdWFsXCI6IFwiNTA2MFwiXG4gICAgICAgIH0sXG4gICAgICAgIFwiY291bnRcIjogXCI4XCIsXG4gICAgICAgIFwiYWN0aW9uXCI6IHtcbiAgICAgICAgICBcImFjdGlvblR5cGVcIjogXCJORVRXT1JLX0NPTk5FQ1RJT05cIixcbiAgICAgICAgICBcIm5ldHdvcmtDb25uZWN0aW9uQWN0aW9uXCI6IHtcbiAgICAgICAgICAgIFwibG9jYWxJcERldGFpbHNcIjoge1xuICAgICAgICAgICAgICBcImlwQWRkcmVzc1Y0XCI6IFwiMTAuMC4wLjI1MVwiXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgXCJwcm90b2NvbFwiOiBcIlRDUFwiLFxuICAgICAgICAgICAgXCJibG9ja2VkXCI6IFwiZmFsc2VcIixcbiAgICAgICAgICAgIFwiY29ubmVjdGlvbkRpcmVjdGlvblwiOiBcIk9VVEJPVU5EXCIsXG4gICAgICAgICAgICBcImxvY2FsUG9ydERldGFpbHNcIjoge1xuICAgICAgICAgICAgICBcInBvcnRcIjogXCIzNjIyMFwiLFxuICAgICAgICAgICAgICBcInBvcnROYW1lXCI6IFwiVW5rbm93blwiXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgXCJyZW1vdGVQb3J0RGV0YWlsc1wiOiB7XG4gICAgICAgICAgICAgIFwicG9ydFwiOiBcIjUwNTBcIixcbiAgICAgICAgICAgICAgXCJwb3J0TmFtZVwiOiBcIlVua25vd25cIlxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIFwicmVtb3RlSXBEZXRhaWxzXCI6IHtcbiAgICAgICAgICAgICAgXCJjb3VudHJ5XCI6IHtcbiAgICAgICAgICAgICAgICBcImNvdW50cnlOYW1lXCI6IFwiVW5pdGVkIFN0YXRlc1wiXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIFwiY2l0eVwiOiB7XG4gICAgICAgICAgICAgICAgXCJjaXR5TmFtZVwiOiBcIldhc2hpbmd0b25cIlxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBcImdlb0xvY2F0aW9uXCI6IHtcbiAgICAgICAgICAgICAgICBcImxvblwiOiBcIi03Ny4wMzE5MDBcIixcbiAgICAgICAgICAgICAgICBcImxhdFwiOiBcIjM4LjkwNTcwMFwiXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIFwib3JnYW5pemF0aW9uXCI6IHtcbiAgICAgICAgICAgICAgICBcImFzbk9yZ1wiOiBcIkFTTi1TdXByZW1lLVdlYlwiLFxuICAgICAgICAgICAgICAgIFwib3JnXCI6IFwiU3VwcmVtZSBXZWJcIixcbiAgICAgICAgICAgICAgICBcImlzcFwiOiBcIlN1cHJlbWUgV2ViXCIsXG4gICAgICAgICAgICAgICAgXCJhc25cIjogXCIzOTU2MDRcIlxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBcImlwQWRkcmVzc1Y0XCI6IFwiOC4yLjE0LjJcIlxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgXCJzZXJ2aWNlTmFtZVwiOiBcImd1YXJkZHV0eVwiXG4gICAgICB9LFxuICAgICAgXCJpZFwiOiBcIjA2YjhkMDYwMmQxMDlkYjEyODJmOTE0MzgwOWY4MGI4XCIsXG4gICAgICBcInJlZ2lvblwiOiBcInVzLWVhc3QtMVwiLFxuICAgICAgXCJhcm5cIjogXCJhcm46YXdzOmd1YXJkZHV0eTp7ZGF0YS5hd3MucmVnaW9ufToxNjYxNTc0NDE3NTg6ZGV0ZWN0b3IvY2FiMzgzOTBiNzI4YzA2ZmIyODk3ZGZjZWJmZmI3OWQvZmluZGluZy8wNmI4ZDA2MDJkMTA5ZGIxMjgyZjkxNDM4MDlmODBiOFwiLFxuICAgICAgXCJ1cGRhdGVkQXRcIjogXCIyMDIwLTA0LTIyVDA3OjE4OjEyLjc3OFpcIlxuICAgIH1cbiAgfSxcbiAgXCJydWxlXCI6IHtcbiAgICBcIm1haWxcIjogZmFsc2UsXG4gICAgXCJsZXZlbFwiOiA2LFxuICAgIFwiZGVzY3JpcHRpb25cIjogXCJBV1MgR3VhcmREdXR5OiBORVRXT1JLX0NPTk5FQ1RJT04gLSBVbnVzdWFsIG91dGJvdW5kIGNvbW11bmljYXRpb24gc2VlbiBmcm9tIEVDMiBpbnN0YW5jZSB7ZGF0YS5hd3MucmVzb3VyY2UuaW5zdGFuY2VEZXRhaWxzLmluc3RhbmNlSWR9IG9uIHNlcnZlciBwb3J0IDUwNjAuXCIsXG4gICAgXCJncm91cHNcIjogW1xuICAgICAgXCJhbWF6b25cIixcbiAgICAgIFwiYXdzXCIsXG4gICAgICBcImF3c19ndWFyZGR1dHlcIlxuICAgIF0sXG4gICAgXCJpZFwiOiBcIjgwMzAyXCJcbiAgfSxcbiAgXCJsb2NhdGlvblwiOiBcIldhenVoLUFXU1wiLFxuICBcImRlY29kZXJcIjoge1xuICAgIFwibmFtZVwiOiBcImpzb25cIlxuICB9LFxufTtcblxuZXhwb3J0IGNvbnN0IGlhbVBvbGljeUdyYW50R2xvYmFsID0ge1xuICBcImRhdGFcIjoge1xuICAgIFwiYXdzXCI6IHtcbiAgICAgIFwic2V2ZXJpdHlcIjogXCJDUklUSUNBTFwiLFxuICAgICAgXCJhY3RvclwiOiBcInJlc291cmNlcy53YXp1aC5zYW1wbGUuY29tXCIsXG4gICAgICBcInN1bW1hcnlcIjoge1xuICAgICAgICBcIlRpbWVzdGFtcHNcIjogXCIyMDIwLTA0LTIyVDAwOjExOjQ0LjYxNzU5N1osXCIsXG4gICAgICAgIFwiRGVzY3JpcHRpb25cIjogXCJTMyBCdWNrZXQgdXNlcyBJQU0gcG9saWN5IHRvIGdyYW50IHJlYWQgcmlnaHRzIHRvIEV2ZXJ5b25lLiBZb3VyIElBTSBwb2xpY3kgY29udGFpbnMgYSBjbGF1c2UgdGhhdCBlZmZlY3RpdmVseSBncmFudHMgcmVhZCBhY2Nlc3MgdG8gYW55IHVzZXIuIFBsZWFzZSBhdWRpdCB0aGlzIGJ1Y2tldCwgYW5kIGRhdGEgY29udGFpbmVkIHdpdGhpbiBhbmQgY29uZmlybSB0aGF0IHRoaXMgaXMgaW50ZW50aW9uYWwuIElmIGludGVudGlvbmFsLCBwbGVhc2UgdXNlIHRoZSBhbGVydCB3aGl0ZWxpc3QgZmVhdHVyZSB0byBwcmV2ZW50IGZ1dHVyZSBhbGVydHNcIixcbiAgICAgICAgXCJCdWNrZXRcIjogXCJyZXNvdXJjZXMud2F6dWguc2FtcGxlLmNvbSxcIixcbiAgICAgICAgXCJSZWNvcmQgQ291bnRcIjogXCIxXCIsXG4gICAgICAgIFwiRXZlbnQgQ291bnRcIjogXCIxXCIsXG4gICAgICAgIFwicmVjaXBpZW50QWNjb3VudElkXCI6IFwiMTY2MTU3NDQxNDAwXCIsXG4gICAgICAgIFwiQUNMXCI6IHtcbiAgICAgICAgICBcInJlc291cmNlc1wiOiB7XG4gICAgICAgICAgICBcIndhenVoXCI6IHtcbiAgICAgICAgICAgICAgXCJjb21cIjoge1xuICAgICAgICAgICAgICAgIFwiT3duZXJcIjoge1xuICAgICAgICAgICAgICAgICAgXCJEaXNwbGF5TmFtZVwiOiBcIndhenVoXCIsXG4gICAgICAgICAgICAgICAgICBcIklEXCI6IFwiM2FiMTIzNWUyNWVhOWU5NGZmOWI3ZTRlMzc5YmE2YjBjODcyY2QzNmMwOTZlMWFjOGNjZTdkZjQzM2I0ODcwMFwiXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgXCJyaXNrLXNjb3JlXCI6IFwiOVwiLFxuICAgICAgXCJub3RpZmljYXRpb24tdHlwZVwiOiBcIkFMRVJUX0NSRUFURURcIixcbiAgICAgIFwibmFtZVwiOiBcIlMzIEJ1Y2tldCBJQU0gcG9saWN5IGdyYW50cyBnbG9iYWwgcmVhZCByaWdodHNcIixcbiAgICAgIFwiY3JlYXRlZC1hdFwiOiBcIjIwMjAtMDQtMjJUMDA6MTQ6NDUuNzY0MDA4XCIsXG4gICAgICBcInNvdXJjZVwiOiBcIm1hY2llXCIsXG4gICAgICBcInVybFwiOiBcImh0dHBzOi8vbXQue2RhdGEuYXdzLnJlZ2lvbn0ubWFjaWUuYXdzLmFtYXpvbi5jb20vcG9zdHMvYXJuJTNBYXdzJTNBbWFjaWUlM0F7ZGF0YS5hd3MucmVnaW9ufSUzQTE2NjE1ODA3NTYyMyUzQXRyaWdnZXIlMkZiNzMxZDlmZmIxZmU2MTUwOGQ0YjQ5MGM5MmVmYTY2NiUyRmFsZXJ0JTJGZDc4ZjBmZDBhNTVhZDQ1ODc5OWU0YzFmYjZhMGVkZWRcIixcbiAgICAgIFwidGFnc1wiOiB7XG4gICAgICAgIFwidmFsdWVcIjogXCJPcGVuIFBlcm1pc3Npb25zLEJhc2ljIEFsZXJ0LFwiXG4gICAgICB9LFxuICAgICAgXCJhbGVydC1hcm5cIjogXCJhcm46YXdzOm1hY2llOntkYXRhLmF3cy5yZWdpb259OjE2NjE1NzQ0MTQwMDp0cmlnZ2VyL2I3MzFkOWZmYjFmZTYxNTA4ZDRhNDc4YzkyZWZhNjY2L2FsZXJ0L2Q3OGYwZmQwYTU1YWQ0NTg3OTllNGMxZmI2YTBlZFwiXG4gICAgfVxuICB9LFxuICBcInJ1bGVcIjoge1xuICAgIFwibWFpbFwiOiB0cnVlLFxuICAgIFwibGV2ZWxcIjogMTIsXG4gICAgXCJkZXNjcmlwdGlvblwiOiBcIkFXUyBNYWNpZSBDUklUSUNBTDogUzMgQnVja2V0IElBTSBwb2xpY3kgZ3JhbnRzIGdsb2JhbCByZWFkIHJpZ2h0cyAtIFMzIEJ1Y2tldCB1c2VzIElBTSBwb2xpY3kgdG8gZ3JhbnQgcmVhZCByaWdodHMgdG8gRXZlcnlvbmUuIFlvdXIgSUFNIHBvbGljeSBjb250YWlucyBhIGNsYXVzZSB0aGF0IGVmZmVjdGl2ZWx5IGdyYW50cyByZWFkIGFjY2VzcyB0byBhbnkgdXNlci4gUGxlYXNlIGF1ZGl0IHRoaXMgYnVja2V0LCBhbmQgZGF0YSBjb250YWluZWQgd2l0aGluIGFuZCBjb25maXJtIHRoYXQgdGhpcyBpcyBpbnRlbnRpb25hbC4gSWYgaW50ZW50aW9uYWwsIHBsZWFzZSB1c2UgdGhlIGFsZXJ0IHdoaXRlbGlzdCBmZWF0dXJlIHRvIHByZXZlbnQgZnV0dXJlIGFsZXJ0c1wiLFxuICAgIFwiZ3JvdXBzXCI6IFtcImFtYXpvblwiLFwiYXdzXCIsXCJhd3NfbWFjaWVcIl0sXG4gICAgXCJpZFwiOiBcIjgwMzU1XCJcbiAgfSxcbiAgXCJsb2NhdGlvblwiOiBcIldhenVoLUFXU1wiLFxuICBcImRlY29kZXJcIjoge1xuICAgIFwibmFtZVwiOiBcImpzb25cIlxuICB9XG59O1xuIl19