"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.USER_NAMES = exports.SERVER_ADDRESS_WEBHOOK = exports.REPOSITORY_NAMES = exports.ORGANIZATION_NAMES = exports.LOCATION = exports.DECODER = exports.COUNTRY_CODES = exports.ALERT_TYPES = exports.ACTORS = void 0;

/*
 * Wazuh app - GitHub sample data
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const LOCATION = 'github';
exports.LOCATION = LOCATION;
const DECODER = {
  "name": "json"
};
exports.DECODER = DECODER;
const COUNTRY_CODES = ['AR', 'CA', 'DE', 'ES', 'FR', 'GR', 'IN', 'MX', 'SE', 'US'];
exports.COUNTRY_CODES = COUNTRY_CODES;
const baseElements = Array(10).fill();
const ORGANIZATION_NAMES = baseElements.map((_, index) => `Organization${index + 1}`);
exports.ORGANIZATION_NAMES = ORGANIZATION_NAMES;
const USER_NAMES = baseElements.map((_, index) => `User${index + 1}`);
exports.USER_NAMES = USER_NAMES;
const REPOSITORY_NAMES = baseElements.map((_, index) => `Repo${index + 1}`);
exports.REPOSITORY_NAMES = REPOSITORY_NAMES;
const ACTORS = baseElements.map((_, index) => ({
  name: USER_NAMES[index],
  country_code: COUNTRY_CODES[index]
}));
exports.ACTORS = ACTORS;
const SERVER_ADDRESS_WEBHOOK = ['https://server/webhook', 'https://cool_server/integrations/webhook', 'https://another_server/github_notifications', 'https://my_web/notifications/webhook'];
exports.SERVER_ADDRESS_WEBHOOK = SERVER_ADDRESS_WEBHOOK;
const ALERT_TYPES = [{
  "rule": {
    "level": 5,
    "description": "GitHub Organization audit log export.",
    "id": "91193",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624444988681.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624444988681.000000",
      "action": "org.audit_log_export",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "ElEQJvOCnhWZ2mVpjzYOMw"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Team create.",
    "id": "91397",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_team"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624445678369.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624445678369.000000",
      "action": "team.create",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "team": "_ORGANIZATION_/_REPOSITORY_",
      "_document_id": "cC4uIXPNDz1O1G21Vjs8Vw"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Team add member.",
    "id": "91393",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_team"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624445678470.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624445678470.000000",
      "action": "team.add_member",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "team": "_ORGANIZATION_/_REPOSITORY_",
      "user": "_USER_",
      "_document_id": "0Z4NBBhHM2T4gEuWziZfvQ"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Team add member.",
    "id": "91393",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_team"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624445927571.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624445927571.000000",
      "action": "team.add_member",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "team": "_ORGANIZATION_/_REPOSITORY_",
      "user": "_USER_",
      "_document_id": "Hi6dpYdi9G5PrEqqTkEYnA"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Repo create.",
    "id": "91318",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_repo"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624445965569.000000",
      "visibility": "private",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "created_at": "1624445965569.000000",
      "action": "repo.create",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "fXwGe7IW-BX8Ze64V_AORg"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git clone.",
    "id": "91158",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "@timestamp": "1624445969188.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "action": "git.clone",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "false"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git clone.",
    "id": "91158",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "@timestamp": "1624446009635.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "action": "git.clone",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "false"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Organization audit log export.",
    "id": "91193",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446236415.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624446236415.000000",
      "action": "org.audit_log_git_event_export",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "vkV52PbNTZPJRRNLuOZcuw"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Organization audit log export.",
    "id": "91193",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446254661.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624446254661.000000",
      "action": "org.audit_log_export",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "gwkccTbAcX2WujhEXS3r0Q"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Team create.",
    "id": "91397",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_team"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446278480.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624446278480.000000",
      "action": "team.create",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "team": "_ORGANIZATION_/_REPOSITORY_",
      "_document_id": "Qf6RhFYhb7ysdV8K8ukYFw"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Team add member.",
    "id": "91393",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_team"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446278606.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624446278606.000000",
      "action": "team.add_member",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "team": "_ORGANIZATION_/_REPOSITORY_",
      "user": "_USER_",
      "_document_id": "T6DZ-t0-a9yQShoBbUxc_g"
    }
  }
}, {
  "rule": {
    "level": 7,
    "description": "GitHub Team destroy.",
    "id": "91399",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_team"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446293390.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624446293390.000000",
      "action": "team.destroy",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "team": "_ORGANIZATION_/_REPOSITORY_",
      "_document_id": "ZLC0q4Ka_R4gGw3gWgxc3w"
    }
  }
}, {
  "rule": {
    "level": 7,
    "description": "GitHub Team remove member.",
    "id": "91401",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_team"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446387691.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624446387691.000000",
      "action": "team.remove_member",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "team": "_ORGANIZATION_/backend",
      "user": "_USER_",
      "_document_id": "PYn3TOghg5FYze673svhgw"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Team add member.",
    "id": "91393",
    "firedtimes": 3,
    "mail": false,
    "groups": ["github", "git", "git_team"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446397464.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624446397464.000000",
      "action": "team.add_member",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "team": "_ORGANIZATION_/backend",
      "user": "_USER_",
      "_document_id": "z4qIP_kjzjnilIhL8ak0mg"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Dependency graph new repos enable.",
    "id": "91131",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_dependency_graph_new_repos"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446915154.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624446915154.000000",
      "action": "dependency_graph_new_repos.enable",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "2Az9XCqb-Fe8k0KkLQlk0A"
    }
  }
}, {
  "rule": {
    "level": 12,
    "description": "GitHub Dependency graph new repos disable.",
    "id": "91130",
    "firedtimes": 1,
    "mail": true,
    "groups": ["github", "git", "git_dependency_graph_new_repos"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446916718.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624446916718.000000",
      "action": "dependency_graph_new_repos.disable",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "TzBGANy3SmrnxI8GW9bpQA"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Hook create.",
    "id": "91162",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_hook"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624446982688.000000",
      "org": "_ORGANIZATION_",
      "hook_id": "303999727",
      "name": "webhook",
      "created_at": "1624446982688.000000",
      "action": "hook.create",
      "active": "true",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "config": {
        "content_type": "json",
        "insecure_ssl": "0",
        "secret": "********",
        "url": "_SERVER_ADDRESS_WEBHOOK_"
      },
      "events": ["push"],
      "_document_id": "SSlObiXNNtzQzxFooK4-fw"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Hook events changed.",
    "id": "91165",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_hook"]
  },
  "data": {
    "integration": "github",
    "github": {
      "org": "_ORGANIZATION_",
      "created_at": "1624447042505.000000",
      "active": "true",
      "actor": "_USER_",
      "@timestamp": "1624447042505.000000",
      "hook_id": "303999727",
      "name": "webhook",
      "action": "hook.events_changed",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "config": {
        "content_type": "json",
        "insecure_ssl": "0",
        "secret": "********",
        "url": "_SERVER_ADDRESS_WEBHOOK_"
      },
      "events": ["push", "create", "deployment", "fork", "issues"],
      "_document_id": "Ba9NJbFnSfJB1zGEn29asw",
      "events_were": ["push"]
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git clone.",
    "id": "91158",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624447139607.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "action": "git.clone",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "false"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git push.",
    "id": "91160",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624447520462.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "action": "git.push",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "false"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git push.",
    "id": "91160",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624447522682.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "action": "git.push",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "false"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git clone.",
    "id": "91158",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "@timestamp": "1624447527007.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "action": "git.clone",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "false"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Repo create.",
    "id": "91318",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_repo"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624447568303.000000",
      "visibility": "private",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "created_at": "1624447568303.000000",
      "action": "repo.create",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "AcrdSmMW0PpEEmuGWiTcoQ"
    }
  }
}, {
  "rule": {
    "level": 9,
    "description": "GitHub Repo destroy.",
    "id": "91320",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_repo"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624447588615.000000",
      "visibility": "private",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "created_at": "1624447588615.000000",
      "action": "repo.destroy",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "H-bRCuWh_FAoZxzW8BV9JA"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git fetch.",
    "id": "91159",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624447744877.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "action": "git.fetch",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "false"
    }
  }
}, {
  "rule": {
    "level": 7,
    "description": "GitHub Organization update default repository permission.",
    "id": "91231",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448015027.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448015027.000000",
      "action": "org.update_default_repository_permission",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "BHpvG7xc2bTNW3ME3nAgDw"
    }
  }
}, {
  "rule": {
    "level": 7,
    "description": "GitHub Organization update default repository permission.",
    "id": "91231",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448020670.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448020670.000000",
      "action": "org.update_default_repository_permission",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "t5ZumMJeWBs2CqZT-n4JNA"
    }
  }
}, {
  "rule": {
    "level": 7,
    "description": "GitHub Organization update member repository creation permission.",
    "id": "91233",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448034735.000000",
      "visibility": "private_internal",
      "org": "_ORGANIZATION_",
      "created_at": "1624448034735.000000",
      "action": "org.update_member_repository_creation_permission",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "CAwbh8KpE75aa0ajCpRISw"
    }
  }
}, {
  "rule": {
    "level": 7,
    "description": "GitHub Organization update member repository creation permission.",
    "id": "91233",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448038247.000000",
      "visibility": "internal",
      "org": "_ORGANIZATION_",
      "created_at": "1624448038247.000000",
      "action": "org.update_member_repository_creation_permission",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "s96ibVD5sEyRDxYgQ8gKhQ"
    }
  }
}, {
  "rule": {
    "level": 9,
    "description": "GitHub Private repository forking enable.",
    "id": "91273",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_private_repository_forking"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448046546.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448046546.000000",
      "action": "private_repository_forking.enable",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "NZWBrO2Ac02LnG3TFeEykA"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Private repository forking disable.",
    "id": "91274",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_private_repository_forking"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448051193.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448051193.000000",
      "action": "private_repository_forking.disable",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "5EkgWPa8Du6ZJ_5oOfU_rg"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Generic rule.",
    "id": "91449",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448069427.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448069427.000000",
      "action": "members_can_create_private_pages.disable",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "0rtyFg2GD2-oJyJsOtRZ_A"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Generic rule.",
    "id": "91449",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448073290.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448073290.000000",
      "action": "members_can_create_private_pages.enable",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "sSbImF40N-hLe0mfDHkfMg"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Generic rule.",
    "id": "91449",
    "firedtimes": 3,
    "mail": false,
    "groups": ["github", "git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448089991.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448089991.000000",
      "action": "repository_visibility_change.enable",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "dWJ-7ZR6DdumQeu01PAGig"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Issues.",
    "id": "91169",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_issues"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448109958.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448109958.000000",
      "action": "issues.deletes_enabled",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "gWT0UNMVFaI8ZPB3tGGsew"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Issues.",
    "id": "91169",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_issues"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448114493.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448114493.000000",
      "action": "issues.deletes_disabled",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "T2hgq3r3yVD23Np6CAD-zQ"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Organization display commenter full name enabled.",
    "id": "91202",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448121171.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448121171.000000",
      "action": "org.display_commenter_full_name_enabled",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "o-Edi8owvz1iPv78RPPSJw"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Organization.",
    "id": "91188",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448125116.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448125116.000000",
      "action": "org.display_commenter_full_name_disabled",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "OxJjqpug2FM8RJuzE1CZpA"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Organization.",
    "id": "91188",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448133245.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448133245.000000",
      "action": "org.enable_reader_discussion_creation_permission",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "5KmA_VkQPn3I6gY4L8qFPA"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Organization.",
    "id": "91188",
    "firedtimes": 3,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448138392.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448138392.000000",
      "action": "org.disable_reader_discussion_creation_permission",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "JQ3JAd3zHmpRpGZYJsJIQw"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Organization enable member team creation permission.",
    "id": "91203",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448148271.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448148271.000000",
      "action": "org.enable_member_team_creation_permission",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "sd2fnKW-Jc_OZI9xm2pyyQ"
    }
  }
}, {
  "rule": {
    "level": 9,
    "description": "GitHub Organization disable member team creation permission.",
    "id": "91198",
    "firedtimes": 1,
    "mail": false,
    "groups": ["github", "git", "git_org"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448154972.000000",
      "org": "_ORGANIZATION_",
      "created_at": "1624448154972.000000",
      "action": "org.disable_member_team_creation_permission",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "ppjVxGQBAQts82at9Az3XQ"
    }
  }
}, {
  "rule": {
    "level": 12,
    "description": "GitHub Repository vulnerability alerts disable.",
    "id": "91367",
    "firedtimes": 1,
    "mail": true,
    "groups": ["github", "git", "git_repository_vulnerability_alerts"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448419210.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "created_at": "1624448419210.000000",
      "action": "repository_vulnerability_alerts.disable",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "user": "_USER_",
      "_document_id": "wgf0uCen5LG4su6jQ2xKDA"
    }
  }
}, {
  "rule": {
    "level": 5,
    "description": "GitHub Repo create.",
    "id": "91318",
    "firedtimes": 2,
    "mail": false,
    "groups": ["github", "git", "git_repo"]
  },
  "data": {
    "integration": "github",
    "github": {
      "actor": "_USER_",
      "@timestamp": "1624448419470.000000",
      "visibility": "public",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "created_at": "1624448419470.000000",
      "action": "repo.create",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "_document_id": "oLAjZ_DbHvzZlPmRCXr4MA"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git clone.",
    "id": "91158",
    "firedtimes": 3,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "@timestamp": "1624448422207.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "action": "git.clone",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "true"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git clone.",
    "id": "91158",
    "firedtimes": 4,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "@timestamp": "1624448423987.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "action": "git.clone",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "true"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git clone.",
    "id": "91158",
    "firedtimes": 5,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "@timestamp": "1624448432101.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "action": "git.clone",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "true"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git clone.",
    "id": "91158",
    "firedtimes": 6,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "@timestamp": "1624448487893.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "action": "git.clone",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "true"
    }
  }
}, {
  "rule": {
    "level": 3,
    "description": "GitHub Git clone.",
    "id": "91158",
    "firedtimes": 7,
    "mail": false,
    "groups": ["github", "git", "git_git"]
  },
  "data": {
    "integration": "github",
    "github": {
      "@timestamp": "1624448736294.000000",
      "org": "_ORGANIZATION_",
      "repo": "_ORGANIZATION_/_REPOSITORY_",
      "actor_location": {
        "country_code": "_COUNTRY_CODE_"
      },
      "action": "git.clone",
      "transport_protocol_name": "http",
      "transport_protocol": "1",
      "repository": "_ORGANIZATION_/_REPOSITORY_",
      "repository_public": "true"
    }
  }
}];
exports.ALERT_TYPES = ALERT_TYPES;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImdpdGh1Yi5qcyJdLCJuYW1lcyI6WyJMT0NBVElPTiIsIkRFQ09ERVIiLCJDT1VOVFJZX0NPREVTIiwiYmFzZUVsZW1lbnRzIiwiQXJyYXkiLCJmaWxsIiwiT1JHQU5JWkFUSU9OX05BTUVTIiwibWFwIiwiXyIsImluZGV4IiwiVVNFUl9OQU1FUyIsIlJFUE9TSVRPUllfTkFNRVMiLCJBQ1RPUlMiLCJuYW1lIiwiY291bnRyeV9jb2RlIiwiU0VSVkVSX0FERFJFU1NfV0VCSE9PSyIsIkFMRVJUX1RZUEVTIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUVPLE1BQU1BLFFBQVEsR0FBRyxRQUFqQjs7QUFFQSxNQUFNQyxPQUFPLEdBQUc7QUFBRSxVQUFRO0FBQVYsQ0FBaEI7O0FBRUEsTUFBTUMsYUFBYSxHQUFHLENBQzNCLElBRDJCLEVBRTNCLElBRjJCLEVBRzNCLElBSDJCLEVBSTNCLElBSjJCLEVBSzNCLElBTDJCLEVBTTNCLElBTjJCLEVBTzNCLElBUDJCLEVBUTNCLElBUjJCLEVBUzNCLElBVDJCLEVBVTNCLElBVjJCLENBQXRCOztBQWFQLE1BQU1DLFlBQVksR0FBR0MsS0FBSyxDQUFDLEVBQUQsQ0FBTCxDQUFVQyxJQUFWLEVBQXJCO0FBRU8sTUFBTUMsa0JBQWtCLEdBQUdILFlBQVksQ0FBQ0ksR0FBYixDQUFpQixDQUFDQyxDQUFELEVBQUlDLEtBQUosS0FBZSxlQUFjQSxLQUFLLEdBQUcsQ0FBRSxFQUF4RCxDQUEzQjs7QUFFQSxNQUFNQyxVQUFVLEdBQUdQLFlBQVksQ0FBQ0ksR0FBYixDQUFpQixDQUFDQyxDQUFELEVBQUlDLEtBQUosS0FBZSxPQUFNQSxLQUFLLEdBQUcsQ0FBRSxFQUFoRCxDQUFuQjs7QUFFQSxNQUFNRSxnQkFBZ0IsR0FBR1IsWUFBWSxDQUFDSSxHQUFiLENBQWlCLENBQUNDLENBQUQsRUFBSUMsS0FBSixLQUFlLE9BQU1BLEtB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QkFBblE7QUFBa1MsMkJBQXFCO0FBQXZUO0FBQXJDO0FBQTdKLENBaER5QixFQWlEekI7QUFBRSxVQUFRO0FBQUUsYUFBUyxDQUFYO0FBQWMsbUJBQWUsbUJBQTdCO0FBQWtELFVBQU0sT0FBeEQ7QUFBaUUsa0JBQWMsQ0FBL0U7QUFBa0YsWUFBUSxLQUExRjtBQUFpRyxjQUFVLENBQUMsUUFBRCxFQUFXLEtBQVgsRUFBa0IsU0FBbEI7QUFBM0csR0FBVjtBQUFxSixVQUFRO0FBQUUsbUJBQWUsUUFBakI7QUFBMkIsY0FBVTtBQUFFLG9CQUFjLHNCQUFoQjtBQUF3QyxhQUFPLGdCQUEvQztBQUFpRSxjQUFRLDZCQUF6RTtBQUF3Ryx3QkFBa0I7QUFBRSx3QkFBZ0I7QUFBbEIsT0FBMUg7QUFBZ0ssZ0JBQVUsV0FBMUs7QUFBdUwsaUNBQTJCLE1BQWxOO0FBQTBOLDRCQUFzQixHQUFoUDtBQUFxUCxvQkFBYyw2QkFBblE7QUFBa1MsMkJBQXFCO0FBQXZUO0FBQXJDO0FBQTdKLENBakR5QixDQUFwQiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBHaXRIdWIgc2FtcGxlIGRhdGFcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5cbmV4cG9ydCBjb25zdCBMT0NBVElPTiA9ICdnaXRodWInO1xuXG5leHBvcnQgY29uc3QgREVDT0RFUiA9IHsgXCJuYW1lXCI6IFwianNvblwiIH07XG5cbmV4cG9ydCBjb25zdCBDT1VOVFJZX0NPREVTID0gW1xuICAnQVInLFxuICAnQ0EnLFxuICAnREUnLFxuICAnRVMnLFxuICAnRlInLFxuICAnR1InLFxuICAnSU4nLFxuICAnTVgnLFxuICAnU0UnLFxuICAnVVMnXG5dO1xuXG5jb25zdCBiYXNlRWxlbWVudHMgPSBBcnJheSgxMCkuZmlsbCgpO1xuXG5leHBvcnQgY29uc3QgT1JHQU5JWkFUSU9OX05BTUVTID0gYmFzZUVsZW1lbnRzLm1hcCgoXywgaW5kZXgpID0+IGBPcmdhbml6YXRpb24ke2luZGV4ICsgMX1gKTtcblxuZXhwb3J0IGNvbnN0IFVTRVJfTkFNRVMgPSBiYXNlRWxlbWVudHMubWFwKChfLCBpbmRleCkgPT4gYFVzZXIke2luZGV4ICsgMX1gKTtcblxuZXhwb3J0IGNvbnN0IFJFUE9TSVRPUllfTkFNRVMgPSBiYXNlRWxlbWVudHMubWFwKChfLCBpbmRleCkgPT4gYFJlcG8ke2luZGV4ICsgMX1gKTtcblxuZXhwb3J0IGNvbnN0IEFDVE9SUyA9IGJhc2VFbGVtZW50cy5tYXAoKF8sIGluZGV4KSA9PiAoeyBuYW1lOiBVU0VSX05BTUVTW2luZGV4XSwgY291bnRyeV9jb2RlOiBDT1VOVFJZX0NPREVTW2luZGV4XSB9KSk7XG5cbmV4cG9ydCBjb25zdCBTRVJWRVJfQUREUkVTU19XRUJIT09LID0gW1xuICAnaHR0cHM6Ly9zZXJ2ZXIvd2ViaG9vaycsXG4gICdodHRwczovL2Nvb2xfc2VydmVyL2ludGVncmF0aW9ucy93ZWJob29rJyxcbiAgJ2h0dHBzOi8vYW5vdGhlcl9zZXJ2ZXIvZ2l0aHViX25vdGlmaWNhdGlvbnMnLFxuICAnaHR0cHM6Ly9teV93ZWIvbm90aWZpY2F0aW9ucy93ZWJob29rJyxcbl07XG5cbmV4cG9ydCBjb25zdCBBTEVSVF9UWVBFUyA9IFtcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDUsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgT3JnYW5pemF0aW9uIGF1ZGl0IGxvZyBleHBvcnQuXCIsIFwiaWRcIjogXCI5MTE5M1wiLCBcImZpcmVkdGltZXNcIjogMSwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfb3JnXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDQ5ODg2ODEuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0NDk4ODY4MS4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJvcmcuYXVkaXRfbG9nX2V4cG9ydFwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwiX2RvY3VtZW50X2lkXCI6IFwiRWxFUUp2T0NuaFdaMm1WcGp6WU9Nd1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBUZWFtIGNyZWF0ZS5cIiwgXCJpZFwiOiBcIjkxMzk3XCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF90ZWFtXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDU2NzgzNjkuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0NTY3ODM2OS4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJ0ZWFtLmNyZWF0ZVwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwidGVhbVwiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcIl9kb2N1bWVudF9pZFwiOiBcImNDNHVJWFBORHoxTzFHMjFWanM4VndcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDUsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgVGVhbSBhZGQgbWVtYmVyLlwiLCBcImlkXCI6IFwiOTEzOTNcIiwgXCJmaXJlZHRpbWVzXCI6IDEsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X3RlYW1cIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NTY3ODQ3MC4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ1Njc4NDcwLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcInRlYW0uYWRkX21lbWJlclwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwidGVhbVwiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcInVzZXJcIjogXCJfVVNFUl9cIiwgXCJfZG9jdW1lbnRfaWRcIjogXCIwWjROQkJoSE0yVDRnRXVXemlaZnZRXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiA1LCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIFRlYW0gYWRkIG1lbWJlci5cIiwgXCJpZFwiOiBcIjkxMzkzXCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF90ZWFtXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDU5Mjc1NzEuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0NTkyNzU3MS4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJ0ZWFtLmFkZF9tZW1iZXJcIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcInRlYW1cIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiSGk2ZHBZZGk5RzVQckVxcVRrRVluQVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBSZXBvIGNyZWF0ZS5cIiwgXCJpZFwiOiBcIjkxMzE4XCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9yZXBvXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDU5NjU1NjkuMDAwMDAwXCIsIFwidmlzaWJpbGl0eVwiOiBcInByaXZhdGVcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcInJlcG9cIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0NTk2NTU2OS4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJyZXBvLmNyZWF0ZVwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwiX2RvY3VtZW50X2lkXCI6IFwiZlh3R2U3SVctQlg4WmU2NFZfQU9SZ1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBHaXQgY2xvbmUuXCIsIFwiaWRcIjogXCI5MTE1OFwiLCBcImZpcmVkdGltZXNcIjogMSwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfZ2l0XCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ1OTY5MTg4LjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwicmVwb1wiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcImFjdGlvblwiOiBcImdpdC5jbG9uZVwiLCBcInRyYW5zcG9ydF9wcm90b2NvbF9uYW1lXCI6IFwiaHR0cFwiLCBcInRyYW5zcG9ydF9wcm90b2NvbFwiOiBcIjFcIiwgXCJyZXBvc2l0b3J5XCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwicmVwb3NpdG9yeV9wdWJsaWNcIjogXCJmYWxzZVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBHaXQgY2xvbmUuXCIsIFwiaWRcIjogXCI5MTE1OFwiLCBcImZpcmVkdGltZXNcIjogMiwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfZ2l0XCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ2MDA5NjM1LjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwicmVwb1wiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcImFjdGlvblwiOiBcImdpdC5jbG9uZVwiLCBcInRyYW5zcG9ydF9wcm90b2NvbF9uYW1lXCI6IFwiaHR0cFwiLCBcInRyYW5zcG9ydF9wcm90b2NvbFwiOiBcIjFcIiwgXCJyZXBvc2l0b3J5XCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwicmVwb3NpdG9yeV9wdWJsaWNcIjogXCJmYWxzZVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBPcmdhbml6YXRpb24gYXVkaXQgbG9nIGV4cG9ydC5cIiwgXCJpZFwiOiBcIjkxMTkzXCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9vcmdcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NjIzNjQxNS4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ2MjM2NDE1LjAwMDAwMFwiLCBcImFjdGlvblwiOiBcIm9yZy5hdWRpdF9sb2dfZ2l0X2V2ZW50X2V4cG9ydFwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwiX2RvY3VtZW50X2lkXCI6IFwidmtWNTJQYk5UWlBKUlJOTHVPWmN1d1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBPcmdhbml6YXRpb24gYXVkaXQgbG9nIGV4cG9ydC5cIiwgXCJpZFwiOiBcIjkxMTkzXCIsIFwiZmlyZWR0aW1lc1wiOiAyLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9vcmdcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NjI1NDY2MS4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ2MjU0NjYxLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcIm9yZy5hdWRpdF9sb2dfZXhwb3J0XCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJfZG9jdW1lbnRfaWRcIjogXCJnd2tjY1RiQWNYMld1amhFWFMzcjBRXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiA1LCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIFRlYW0gY3JlYXRlLlwiLCBcImlkXCI6IFwiOTEzOTdcIiwgXCJmaXJlZHRpbWVzXCI6IDEsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X3RlYW1cIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NjI3ODQ4MC4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ2Mjc4NDgwLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcInRlYW0uY3JlYXRlXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ0ZWFtXCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiUWY2UmhGWWhiN3lzZFY4Szh1a1lGd1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBUZWFtIGFkZCBtZW1iZXIuXCIsIFwiaWRcIjogXCI5MTM5M1wiLCBcImZpcmVkdGltZXNcIjogMiwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfdGVhbVwiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ2Mjc4NjA2LjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwiY3JlYXRlZF9hdFwiOiBcIjE2MjQ0NDYyNzg2MDYuMDAwMDAwXCIsIFwiYWN0aW9uXCI6IFwidGVhbS5hZGRfbWVtYmVyXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ0ZWFtXCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwidXNlclwiOiBcIl9VU0VSX1wiLCBcIl9kb2N1bWVudF9pZFwiOiBcIlQ2RFotdDAtYTl5UVNob0JiVXhjX2dcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDcsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgVGVhbSBkZXN0cm95LlwiLCBcImlkXCI6IFwiOTEzOTlcIiwgXCJmaXJlZHRpbWVzXCI6IDEsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X3RlYW1cIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NjI5MzM5MC4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ2MjkzMzkwLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcInRlYW0uZGVzdHJveVwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwidGVhbVwiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcIl9kb2N1bWVudF9pZFwiOiBcIlpMQzBxNEthX1I0Z0d3M2dXZ3hjM3dcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDcsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgVGVhbSByZW1vdmUgbWVtYmVyLlwiLCBcImlkXCI6IFwiOTE0MDFcIiwgXCJmaXJlZHRpbWVzXCI6IDEsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X3RlYW1cIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NjM4NzY5MS4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ2Mzg3NjkxLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcInRlYW0ucmVtb3ZlX21lbWJlclwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwidGVhbVwiOiBcIl9PUkdBTklaQVRJT05fL2JhY2tlbmRcIiwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiUFluM1RPZ2hnNUZZemU2NzNzdmhnd1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBUZWFtIGFkZCBtZW1iZXIuXCIsIFwiaWRcIjogXCI5MTM5M1wiLCBcImZpcmVkdGltZXNcIjogMywgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfdGVhbVwiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ2Mzk3NDY0LjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwiY3JlYXRlZF9hdFwiOiBcIjE2MjQ0NDYzOTc0NjQuMDAwMDAwXCIsIFwiYWN0aW9uXCI6IFwidGVhbS5hZGRfbWVtYmVyXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ0ZWFtXCI6IFwiX09SR0FOSVpBVElPTl8vYmFja2VuZFwiLCBcInVzZXJcIjogXCJfVVNFUl9cIiwgXCJfZG9jdW1lbnRfaWRcIjogXCJ6NHFJUF9ranpqbmlsSWhMOGFrMG1nXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiAzLCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIERlcGVuZGVuY3kgZ3JhcGggbmV3IHJlcG9zIGVuYWJsZS5cIiwgXCJpZFwiOiBcIjkxMTMxXCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9kZXBlbmRlbmN5X2dyYXBoX25ld19yZXBvc1wiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ2OTE1MTU0LjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwiY3JlYXRlZF9hdFwiOiBcIjE2MjQ0NDY5MTUxNTQuMDAwMDAwXCIsIFwiYWN0aW9uXCI6IFwiZGVwZW5kZW5jeV9ncmFwaF9uZXdfcmVwb3MuZW5hYmxlXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiMkF6OVhDcWItRmU4azBLa0xRbGswQVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMTIsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgRGVwZW5kZW5jeSBncmFwaCBuZXcgcmVwb3MgZGlzYWJsZS5cIiwgXCJpZFwiOiBcIjkxMTMwXCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogdHJ1ZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X2RlcGVuZGVuY3lfZ3JhcGhfbmV3X3JlcG9zXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDY5MTY3MTguMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0NjkxNjcxOC4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJkZXBlbmRlbmN5X2dyYXBoX25ld19yZXBvcy5kaXNhYmxlXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiVHpCR0FOeTNTbXJueEk4R1c5YnBRQVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBIb29rIGNyZWF0ZS5cIiwgXCJpZFwiOiBcIjkxMTYyXCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9ob29rXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDY5ODI2ODguMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJob29rX2lkXCI6IFwiMzAzOTk5NzI3XCIsIFwibmFtZVwiOiBcIndlYmhvb2tcIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0Njk4MjY4OC4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJob29rLmNyZWF0ZVwiLCBcImFjdGl2ZVwiOiBcInRydWVcIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcImNvbmZpZ1wiOiB7IFwiY29udGVudF90eXBlXCI6IFwianNvblwiLCBcImluc2VjdXJlX3NzbFwiOiBcIjBcIiwgXCJzZWNyZXRcIjogXCIqKioqKioqKlwiLCBcInVybFwiOiBcIl9TRVJWRVJfQUREUkVTU19XRUJIT09LX1wiIH0sIFwiZXZlbnRzXCI6IFtcInB1c2hcIl0sIFwiX2RvY3VtZW50X2lkXCI6IFwiU1NsT2JpWE5OdHpRenhGb29LNC1md1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBIb29rIGV2ZW50cyBjaGFuZ2VkLlwiLCBcImlkXCI6IFwiOTExNjVcIiwgXCJmaXJlZHRpbWVzXCI6IDEsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X2hvb2tcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0NzA0MjUwNS4wMDAwMDBcIiwgXCJhY3RpdmVcIjogXCJ0cnVlXCIsIFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NzA0MjUwNS4wMDAwMDBcIiwgXCJob29rX2lkXCI6IFwiMzAzOTk5NzI3XCIsIFwibmFtZVwiOiBcIndlYmhvb2tcIiwgXCJhY3Rpb25cIjogXCJob29rLmV2ZW50c19jaGFuZ2VkXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJjb25maWdcIjogeyBcImNvbnRlbnRfdHlwZVwiOiBcImpzb25cIiwgXCJpbnNlY3VyZV9zc2xcIjogXCIwXCIsIFwic2VjcmV0XCI6IFwiKioqKioqKipcIiwgXCJ1cmxcIjogXCJfU0VSVkVSX0FERFJFU1NfV0VCSE9PS19cIiB9LCBcImV2ZW50c1wiOiBbXCJwdXNoXCIsIFwiY3JlYXRlXCIsIFwiZGVwbG95bWVudFwiLCBcImZvcmtcIiwgXCJpc3N1ZXNcIl0sIFwiX2RvY3VtZW50X2lkXCI6IFwiQmE5TkpiRm5TZkpCMXpHRW4yOWFzd1wiLCBcImV2ZW50c193ZXJlXCI6IFtcInB1c2hcIl0gfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiAzLCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIEdpdCBjbG9uZS5cIiwgXCJpZFwiOiBcIjkxMTU4XCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9naXRcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NzEzOTYwNy4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcInJlcG9cIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcImFjdGlvblwiOiBcImdpdC5jbG9uZVwiLCBcInRyYW5zcG9ydF9wcm90b2NvbF9uYW1lXCI6IFwiaHR0cFwiLCBcInRyYW5zcG9ydF9wcm90b2NvbFwiOiBcIjFcIiwgXCJyZXBvc2l0b3J5XCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwicmVwb3NpdG9yeV9wdWJsaWNcIjogXCJmYWxzZVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBHaXQgcHVzaC5cIiwgXCJpZFwiOiBcIjkxMTYwXCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9naXRcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NzUyMDQ2Mi4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcInJlcG9cIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcImFjdGlvblwiOiBcImdpdC5wdXNoXCIsIFwidHJhbnNwb3J0X3Byb3RvY29sX25hbWVcIjogXCJodHRwXCIsIFwidHJhbnNwb3J0X3Byb3RvY29sXCI6IFwiMVwiLCBcInJlcG9zaXRvcnlcIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJyZXBvc2l0b3J5X3B1YmxpY1wiOiBcImZhbHNlXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiAzLCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIEdpdCBwdXNoLlwiLCBcImlkXCI6IFwiOTExNjBcIiwgXCJmaXJlZHRpbWVzXCI6IDIsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X2dpdFwiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ3NTIyNjgyLjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwicmVwb1wiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwiYWN0aW9uXCI6IFwiZ2l0LnB1c2hcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xfbmFtZVwiOiBcImh0dHBcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xcIjogXCIxXCIsIFwicmVwb3NpdG9yeVwiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcInJlcG9zaXRvcnlfcHVibGljXCI6IFwiZmFsc2VcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDMsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgR2l0IGNsb25lLlwiLCBcImlkXCI6IFwiOTExNThcIiwgXCJmaXJlZHRpbWVzXCI6IDIsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X2dpdFwiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NzUyNzAwNy4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcInJlcG9cIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJhY3Rpb25cIjogXCJnaXQuY2xvbmVcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xfbmFtZVwiOiBcImh0dHBcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xcIjogXCIxXCIsIFwicmVwb3NpdG9yeVwiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcInJlcG9zaXRvcnlfcHVibGljXCI6IFwiZmFsc2VcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDUsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgUmVwbyBjcmVhdGUuXCIsIFwiaWRcIjogXCI5MTMxOFwiLCBcImZpcmVkdGltZXNcIjogMSwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfcmVwb1wiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ3NTY4MzAzLjAwMDAwMFwiLCBcInZpc2liaWxpdHlcIjogXCJwcml2YXRlXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJyZXBvXCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwiY3JlYXRlZF9hdFwiOiBcIjE2MjQ0NDc1NjgzMDMuMDAwMDAwXCIsIFwiYWN0aW9uXCI6IFwicmVwby5jcmVhdGVcIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcIl9kb2N1bWVudF9pZFwiOiBcIkFjcmRTbU1XMFBwRUVtdUdXaVRjb1FcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDksIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgUmVwbyBkZXN0cm95LlwiLCBcImlkXCI6IFwiOTEzMjBcIiwgXCJmaXJlZHRpbWVzXCI6IDEsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X3JlcG9cIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0NzU4ODYxNS4wMDAwMDBcIiwgXCJ2aXNpYmlsaXR5XCI6IFwicHJpdmF0ZVwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwicmVwb1wiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ3NTg4NjE1LjAwMDAwMFwiLCBcImFjdGlvblwiOiBcInJlcG8uZGVzdHJveVwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwiX2RvY3VtZW50X2lkXCI6IFwiSC1iUkN1V2hfRkFvWnh6VzhCVjlKQVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBHaXQgZmV0Y2guXCIsIFwiaWRcIjogXCI5MTE1OVwiLCBcImZpcmVkdGltZXNcIjogMSwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfZ2l0XCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDc3NDQ4NzcuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJyZXBvXCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJhY3Rpb25cIjogXCJnaXQuZmV0Y2hcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xfbmFtZVwiOiBcImh0dHBcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xcIjogXCIxXCIsIFwicmVwb3NpdG9yeVwiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcInJlcG9zaXRvcnlfcHVibGljXCI6IFwiZmFsc2VcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDcsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgT3JnYW5pemF0aW9uIHVwZGF0ZSBkZWZhdWx0IHJlcG9zaXRvcnkgcGVybWlzc2lvbi5cIiwgXCJpZFwiOiBcIjkxMjMxXCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9vcmdcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0ODAxNTAyNy4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ4MDE1MDI3LjAwMDAwMFwiLCBcImFjdGlvblwiOiBcIm9yZy51cGRhdGVfZGVmYXVsdF9yZXBvc2l0b3J5X3Blcm1pc3Npb25cIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcIl9kb2N1bWVudF9pZFwiOiBcIkJIcHZHN3hjMmJUTlczTUUzbkFnRHdcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDcsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgT3JnYW5pemF0aW9uIHVwZGF0ZSBkZWZhdWx0IHJlcG9zaXRvcnkgcGVybWlzc2lvbi5cIiwgXCJpZFwiOiBcIjkxMjMxXCIsIFwiZmlyZWR0aW1lc1wiOiAyLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9vcmdcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0ODAyMDY3MC4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ4MDIwNjcwLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcIm9yZy51cGRhdGVfZGVmYXVsdF9yZXBvc2l0b3J5X3Blcm1pc3Npb25cIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcIl9kb2N1bWVudF9pZFwiOiBcInQ1WnVtTUplV0JzMkNxWlQtbjRKTkFcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDcsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgT3JnYW5pemF0aW9uIHVwZGF0ZSBtZW1iZXIgcmVwb3NpdG9yeSBjcmVhdGlvbiBwZXJtaXNzaW9uLlwiLCBcImlkXCI6IFwiOTEyMzNcIiwgXCJmaXJlZHRpbWVzXCI6IDEsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X29yZ1wiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ4MDM0NzM1LjAwMDAwMFwiLCBcInZpc2liaWxpdHlcIjogXCJwcml2YXRlX2ludGVybmFsXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0ODAzNDczNS4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJvcmcudXBkYXRlX21lbWJlcl9yZXBvc2l0b3J5X2NyZWF0aW9uX3Blcm1pc3Npb25cIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcIl9kb2N1bWVudF9pZFwiOiBcIkNBd2JoOEtwRTc1YWEwYWpDcFJJU3dcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDcsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgT3JnYW5pemF0aW9uIHVwZGF0ZSBtZW1iZXIgcmVwb3NpdG9yeSBjcmVhdGlvbiBwZXJtaXNzaW9uLlwiLCBcImlkXCI6IFwiOTEyMzNcIiwgXCJmaXJlZHRpbWVzXCI6IDIsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X29yZ1wiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ4MDM4MjQ3LjAwMDAwMFwiLCBcInZpc2liaWxpdHlcIjogXCJpbnRlcm5hbFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwiY3JlYXRlZF9hdFwiOiBcIjE2MjQ0NDgwMzgyNDcuMDAwMDAwXCIsIFwiYWN0aW9uXCI6IFwib3JnLnVwZGF0ZV9tZW1iZXJfcmVwb3NpdG9yeV9jcmVhdGlvbl9wZXJtaXNzaW9uXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJfZG9jdW1lbnRfaWRcIjogXCJzOTZpYlZENXNFeVJEeFlnUThnS2hRXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiA5LCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIFByaXZhdGUgcmVwb3NpdG9yeSBmb3JraW5nIGVuYWJsZS5cIiwgXCJpZFwiOiBcIjkxMjczXCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9wcml2YXRlX3JlcG9zaXRvcnlfZm9ya2luZ1wiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ4MDQ2NTQ2LjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwiY3JlYXRlZF9hdFwiOiBcIjE2MjQ0NDgwNDY1NDYuMDAwMDAwXCIsIFwiYWN0aW9uXCI6IFwicHJpdmF0ZV9yZXBvc2l0b3J5X2ZvcmtpbmcuZW5hYmxlXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiTlpXQnJPMkFjMDJMbkczVEZlRXlrQVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBQcml2YXRlIHJlcG9zaXRvcnkgZm9ya2luZyBkaXNhYmxlLlwiLCBcImlkXCI6IFwiOTEyNzRcIiwgXCJmaXJlZHRpbWVzXCI6IDEsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X3ByaXZhdGVfcmVwb3NpdG9yeV9mb3JraW5nXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDgwNTExOTMuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0ODA1MTE5My4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJwcml2YXRlX3JlcG9zaXRvcnlfZm9ya2luZy5kaXNhYmxlXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiNUVrZ1dQYThEdTZaSl81b09mVV9yZ1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBHZW5lcmljIHJ1bGUuXCIsIFwiaWRcIjogXCI5MTQ0OVwiLCBcImZpcmVkdGltZXNcIjogMSwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0ODA2OTQyNy4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ4MDY5NDI3LjAwMDAwMFwiLCBcImFjdGlvblwiOiBcIm1lbWJlcnNfY2FuX2NyZWF0ZV9wcml2YXRlX3BhZ2VzLmRpc2FibGVcIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcInVzZXJcIjogXCJfVVNFUl9cIiwgXCJfZG9jdW1lbnRfaWRcIjogXCIwcnR5RmcyR0QyLW9KeUpzT3RSWl9BXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiAzLCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIEdlbmVyaWMgcnVsZS5cIiwgXCJpZFwiOiBcIjkxNDQ5XCIsIFwiZmlyZWR0aW1lc1wiOiAyLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ4MDczMjkwLjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwiY3JlYXRlZF9hdFwiOiBcIjE2MjQ0NDgwNzMyOTAuMDAwMDAwXCIsIFwiYWN0aW9uXCI6IFwibWVtYmVyc19jYW5fY3JlYXRlX3ByaXZhdGVfcGFnZXMuZW5hYmxlXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwic1NiSW1GNDBOLWhMZTBtZkRIa2ZNZ1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBHZW5lcmljIHJ1bGUuXCIsIFwiaWRcIjogXCI5MTQ0OVwiLCBcImZpcmVkdGltZXNcIjogMywgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0ODA4OTk5MS4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ4MDg5OTkxLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcInJlcG9zaXRvcnlfdmlzaWJpbGl0eV9jaGFuZ2UuZW5hYmxlXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiZFdKLTdaUjZEZHVtUWV1MDFQQUdpZ1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBJc3N1ZXMuXCIsIFwiaWRcIjogXCI5MTE2OVwiLCBcImZpcmVkdGltZXNcIjogMSwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfaXNzdWVzXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDgxMDk5NTguMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0ODEwOTk1OC4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJpc3N1ZXMuZGVsZXRlc19lbmFibGVkXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiZ1dUMFVOTVZGYUk4WlBCM3RHR3Nld1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBJc3N1ZXMuXCIsIFwiaWRcIjogXCI5MTE2OVwiLCBcImZpcmVkdGltZXNcIjogMiwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfaXNzdWVzXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDgxMTQ0OTMuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0ODExNDQ5My4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJpc3N1ZXMuZGVsZXRlc19kaXNhYmxlZFwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwidXNlclwiOiBcIl9VU0VSX1wiLCBcIl9kb2N1bWVudF9pZFwiOiBcIlQyaGdxM3IzeVZEMjNOcDZDQUQtelFcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDUsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgT3JnYW5pemF0aW9uIGRpc3BsYXkgY29tbWVudGVyIGZ1bGwgbmFtZSBlbmFibGVkLlwiLCBcImlkXCI6IFwiOTEyMDJcIiwgXCJmaXJlZHRpbWVzXCI6IDEsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X29yZ1wiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJhY3RvclwiOiBcIl9VU0VSX1wiLCBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ4MTIxMTcxLjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwiY3JlYXRlZF9hdFwiOiBcIjE2MjQ0NDgxMjExNzEuMDAwMDAwXCIsIFwiYWN0aW9uXCI6IFwib3JnLmRpc3BsYXlfY29tbWVudGVyX2Z1bGxfbmFtZV9lbmFibGVkXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiby1FZGk4b3d2ejFpUHY3OFJQUFNKd1wiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBPcmdhbml6YXRpb24uXCIsIFwiaWRcIjogXCI5MTE4OFwiLCBcImZpcmVkdGltZXNcIjogMSwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfb3JnXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDgxMjUxMTYuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0ODEyNTExNi4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJvcmcuZGlzcGxheV9jb21tZW50ZXJfZnVsbF9uYW1lX2Rpc2FibGVkXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwiT3hKanFwdWcyRk04Ukp1ekUxQ1pwQVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBPcmdhbml6YXRpb24uXCIsIFwiaWRcIjogXCI5MTE4OFwiLCBcImZpcmVkdGltZXNcIjogMiwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfb3JnXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDgxMzMyNDUuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJjcmVhdGVkX2F0XCI6IFwiMTYyNDQ0ODEzMzI0NS4wMDAwMDBcIiwgXCJhY3Rpb25cIjogXCJvcmcuZW5hYmxlX3JlYWRlcl9kaXNjdXNzaW9uX2NyZWF0aW9uX3Blcm1pc3Npb25cIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcInVzZXJcIjogXCJfVVNFUl9cIiwgXCJfZG9jdW1lbnRfaWRcIjogXCI1S21BX1ZrUVBuM0k2Z1k0TDhxRlBBXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiAzLCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIE9yZ2FuaXphdGlvbi5cIiwgXCJpZFwiOiBcIjkxMTg4XCIsIFwiZmlyZWR0aW1lc1wiOiAzLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9vcmdcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0ODEzODM5Mi4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ4MTM4MzkyLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcIm9yZy5kaXNhYmxlX3JlYWRlcl9kaXNjdXNzaW9uX2NyZWF0aW9uX3Blcm1pc3Npb25cIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcInVzZXJcIjogXCJfVVNFUl9cIiwgXCJfZG9jdW1lbnRfaWRcIjogXCJKUTNKQWQzekhtcFJwR1pZSnNKSVF3XCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiA1LCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIE9yZ2FuaXphdGlvbiBlbmFibGUgbWVtYmVyIHRlYW0gY3JlYXRpb24gcGVybWlzc2lvbi5cIiwgXCJpZFwiOiBcIjkxMjAzXCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9vcmdcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0ODE0ODI3MS4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ4MTQ4MjcxLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcIm9yZy5lbmFibGVfbWVtYmVyX3RlYW1fY3JlYXRpb25fcGVybWlzc2lvblwiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwidXNlclwiOiBcIl9VU0VSX1wiLCBcIl9kb2N1bWVudF9pZFwiOiBcInNkMmZuS1ctSmNfT1pJOXhtMnB5eVFcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDksIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgT3JnYW5pemF0aW9uIGRpc2FibGUgbWVtYmVyIHRlYW0gY3JlYXRpb24gcGVybWlzc2lvbi5cIiwgXCJpZFwiOiBcIjkxMTk4XCIsIFwiZmlyZWR0aW1lc1wiOiAxLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9vcmdcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiYWN0b3JcIjogXCJfVVNFUl9cIiwgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0ODE1NDk3Mi4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ4MTU0OTcyLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcIm9yZy5kaXNhYmxlX21lbWJlcl90ZWFtX2NyZWF0aW9uX3Blcm1pc3Npb25cIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcInVzZXJcIjogXCJfVVNFUl9cIiwgXCJfZG9jdW1lbnRfaWRcIjogXCJwcGpWeEdRQkFRdHM4MmF0OUF6M1hRXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiAxMiwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBSZXBvc2l0b3J5IHZ1bG5lcmFiaWxpdHkgYWxlcnRzIGRpc2FibGUuXCIsIFwiaWRcIjogXCI5MTM2N1wiLCBcImZpcmVkdGltZXNcIjogMSwgXCJtYWlsXCI6IHRydWUsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9yZXBvc2l0b3J5X3Z1bG5lcmFiaWxpdHlfYWxlcnRzXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDg0MTkyMTAuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJyZXBvXCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwiY3JlYXRlZF9hdFwiOiBcIjE2MjQ0NDg0MTkyMTAuMDAwMDAwXCIsIFwiYWN0aW9uXCI6IFwicmVwb3NpdG9yeV92dWxuZXJhYmlsaXR5X2FsZXJ0cy5kaXNhYmxlXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJ1c2VyXCI6IFwiX1VTRVJfXCIsIFwiX2RvY3VtZW50X2lkXCI6IFwid2dmMHVDZW41TEc0c3U2alEyeEtEQVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogNSwgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBSZXBvIGNyZWF0ZS5cIiwgXCJpZFwiOiBcIjkxMzE4XCIsIFwiZmlyZWR0aW1lc1wiOiAyLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9yZXBvXCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcImFjdG9yXCI6IFwiX1VTRVJfXCIsIFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDg0MTk0NzAuMDAwMDAwXCIsIFwidmlzaWJpbGl0eVwiOiBcInB1YmxpY1wiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwicmVwb1wiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcImNyZWF0ZWRfYXRcIjogXCIxNjI0NDQ4NDE5NDcwLjAwMDAwMFwiLCBcImFjdGlvblwiOiBcInJlcG8uY3JlYXRlXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJfZG9jdW1lbnRfaWRcIjogXCJvTEFqWl9EYkh2elpsUG1SQ1hyNE1BXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiAzLCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIEdpdCBjbG9uZS5cIiwgXCJpZFwiOiBcIjkxMTU4XCIsIFwiZmlyZWR0aW1lc1wiOiAzLCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9naXRcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDg0MjIyMDcuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJyZXBvXCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwiYWN0aW9uXCI6IFwiZ2l0LmNsb25lXCIsIFwidHJhbnNwb3J0X3Byb3RvY29sX25hbWVcIjogXCJodHRwXCIsIFwidHJhbnNwb3J0X3Byb3RvY29sXCI6IFwiMVwiLCBcInJlcG9zaXRvcnlcIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJyZXBvc2l0b3J5X3B1YmxpY1wiOiBcInRydWVcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDMsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgR2l0IGNsb25lLlwiLCBcImlkXCI6IFwiOTExNThcIiwgXCJmaXJlZHRpbWVzXCI6IDQsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X2dpdFwiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0ODQyMzk4Ny4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcInJlcG9cIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJhY3Rpb25cIjogXCJnaXQuY2xvbmVcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xfbmFtZVwiOiBcImh0dHBcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xcIjogXCIxXCIsIFwicmVwb3NpdG9yeVwiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcInJlcG9zaXRvcnlfcHVibGljXCI6IFwidHJ1ZVwiIH0gfSB9LFxuICB7IFwicnVsZVwiOiB7IFwibGV2ZWxcIjogMywgXCJkZXNjcmlwdGlvblwiOiBcIkdpdEh1YiBHaXQgY2xvbmUuXCIsIFwiaWRcIjogXCI5MTE1OFwiLCBcImZpcmVkdGltZXNcIjogNSwgXCJtYWlsXCI6IGZhbHNlLCBcImdyb3Vwc1wiOiBbXCJnaXRodWJcIiwgXCJnaXRcIiwgXCJnaXRfZ2l0XCJdIH0sIFwiZGF0YVwiOiB7IFwiaW50ZWdyYXRpb25cIjogXCJnaXRodWJcIiwgXCJnaXRodWJcIjogeyBcIkB0aW1lc3RhbXBcIjogXCIxNjI0NDQ4NDMyMTAxLjAwMDAwMFwiLCBcIm9yZ1wiOiBcIl9PUkdBTklaQVRJT05fXCIsIFwicmVwb1wiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcImFjdG9yX2xvY2F0aW9uXCI6IHsgXCJjb3VudHJ5X2NvZGVcIjogXCJfQ09VTlRSWV9DT0RFX1wiIH0sIFwiYWN0aW9uXCI6IFwiZ2l0LmNsb25lXCIsIFwidHJhbnNwb3J0X3Byb3RvY29sX25hbWVcIjogXCJodHRwXCIsIFwidHJhbnNwb3J0X3Byb3RvY29sXCI6IFwiMVwiLCBcInJlcG9zaXRvcnlcIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJyZXBvc2l0b3J5X3B1YmxpY1wiOiBcInRydWVcIiB9IH0gfSxcbiAgeyBcInJ1bGVcIjogeyBcImxldmVsXCI6IDMsIFwiZGVzY3JpcHRpb25cIjogXCJHaXRIdWIgR2l0IGNsb25lLlwiLCBcImlkXCI6IFwiOTExNThcIiwgXCJmaXJlZHRpbWVzXCI6IDYsIFwibWFpbFwiOiBmYWxzZSwgXCJncm91cHNcIjogW1wiZ2l0aHViXCIsIFwiZ2l0XCIsIFwiZ2l0X2dpdFwiXSB9LCBcImRhdGFcIjogeyBcImludGVncmF0aW9uXCI6IFwiZ2l0aHViXCIsIFwiZ2l0aHViXCI6IHsgXCJAdGltZXN0YW1wXCI6IFwiMTYyNDQ0ODQ4Nzg5My4wMDAwMDBcIiwgXCJvcmdcIjogXCJfT1JHQU5JWkFUSU9OX1wiLCBcInJlcG9cIjogXCJfT1JHQU5JWkFUSU9OXy9fUkVQT1NJVE9SWV9cIiwgXCJhY3Rvcl9sb2NhdGlvblwiOiB7IFwiY291bnRyeV9jb2RlXCI6IFwiX0NPVU5UUllfQ09ERV9cIiB9LCBcImFjdGlvblwiOiBcImdpdC5jbG9uZVwiLCBcInRyYW5zcG9ydF9wcm90b2NvbF9uYW1lXCI6IFwiaHR0cFwiLCBcInRyYW5zcG9ydF9wcm90b2NvbFwiOiBcIjFcIiwgXCJyZXBvc2l0b3J5XCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwicmVwb3NpdG9yeV9wdWJsaWNcIjogXCJ0cnVlXCIgfSB9IH0sXG4gIHsgXCJydWxlXCI6IHsgXCJsZXZlbFwiOiAzLCBcImRlc2NyaXB0aW9uXCI6IFwiR2l0SHViIEdpdCBjbG9uZS5cIiwgXCJpZFwiOiBcIjkxMTU4XCIsIFwiZmlyZWR0aW1lc1wiOiA3LCBcIm1haWxcIjogZmFsc2UsIFwiZ3JvdXBzXCI6IFtcImdpdGh1YlwiLCBcImdpdFwiLCBcImdpdF9naXRcIl0gfSwgXCJkYXRhXCI6IHsgXCJpbnRlZ3JhdGlvblwiOiBcImdpdGh1YlwiLCBcImdpdGh1YlwiOiB7IFwiQHRpbWVzdGFtcFwiOiBcIjE2MjQ0NDg3MzYyOTQuMDAwMDAwXCIsIFwib3JnXCI6IFwiX09SR0FOSVpBVElPTl9cIiwgXCJyZXBvXCI6IFwiX09SR0FOSVpBVElPTl8vX1JFUE9TSVRPUllfXCIsIFwiYWN0b3JfbG9jYXRpb25cIjogeyBcImNvdW50cnlfY29kZVwiOiBcIl9DT1VOVFJZX0NPREVfXCIgfSwgXCJhY3Rpb25cIjogXCJnaXQuY2xvbmVcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xfbmFtZVwiOiBcImh0dHBcIiwgXCJ0cmFuc3BvcnRfcHJvdG9jb2xcIjogXCIxXCIsIFwicmVwb3NpdG9yeVwiOiBcIl9PUkdBTklaQVRJT05fL19SRVBPU0lUT1JZX1wiLCBcInJlcG9zaXRvcnlfcHVibGljXCI6IFwidHJ1ZVwiIH0gfSB9LFxuXTtcbiJdfQ==