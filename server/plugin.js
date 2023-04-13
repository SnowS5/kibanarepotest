"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhPlugin = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _securityFactory = require("./lib/security-factory");

var _routes = require("./routes");

var _start = require("./start");

var _cookie = require("./lib/cookie");

var ApiInterceptor = _interopRequireWildcard(require("./lib/api-interceptor"));

var _operators = require("rxjs/operators");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

/*
 * Licensed to Elasticsearch B.V. under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch B.V. licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
class WazuhPlugin {
  constructor(initializerContext) {
    (0, _defineProperty2.default)(this, "logger", void 0);
    this.initializerContext = initializerContext;
    this.logger = initializerContext.logger.get();
  }

  async setup(core, plugins) {
    this.logger.debug('Wazuh-wui: Setup');
    const serverInfo = core.http.getServerInfo();
    let wazuhSecurity;
    core.http.registerRouteHandlerContext('wazuh', async (context, request) => {
      !wazuhSecurity && (wazuhSecurity = await (0, _securityFactory.SecurityObj)(plugins, context));
      return {
        logger: this.logger,
        server: {
          info: serverInfo
        },
        plugins,
        security: wazuhSecurity,
        api: {
          client: {
            asInternalUser: {
              authenticate: async apiHostID => await ApiInterceptor.authenticate(apiHostID),
              request: async (method, path, data, options) => await ApiInterceptor.requestAsInternalUser(method, path, data, options)
            },
            asCurrentUser: {
              authenticate: async apiHostID => await ApiInterceptor.authenticate(apiHostID, (await wazuhSecurity.getCurrentUser(request, context)).authContext),
              request: async (method, path, data, options) => await ApiInterceptor.requestAsCurrentUser(method, path, data, { ...options,
                token: (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token')
              })
            }
          }
        }
      };
    }); // Add custom headers to the responses

    core.http.registerOnPreResponse((request, response, toolkit) => {
      const additionalHeaders = {
        'x-frame-options': 'sameorigin'
      };
      return toolkit.next({
        headers: additionalHeaders
      });
    }); // Routes

    const router = core.http.createRouter();
    (0, _routes.setupRoutes)(router);
    return {};
  }

  async start(core) {
    const globalConfiguration = await this.initializerContext.config.legacy.globalConfig$.pipe((0, _operators.first)()).toPromise();
    const wazuhApiClient = {
      client: {
        asInternalUser: {
          authenticate: async apiHostID => await ApiInterceptor.authenticate(apiHostID),
          request: async (method, path, data, options) => await ApiInterceptor.requestAsInternalUser(method, path, data, options)
        }
      }
    };
    const contextServer = {
      config: globalConfiguration
    }; // Initialize

    (0, _start.jobInitializeRun)({
      core,
      wazuh: {
        logger: this.logger.get('initialize'),
        api: wazuhApiClient
      },
      server: contextServer
    }); // Migration tasks

    (0, _start.jobMigrationTasksRun)({
      core,
      wazuh: {
        logger: this.logger.get('migration-task'),
        api: wazuhApiClient
      },
      server: contextServer
    }); // Monitoring

    (0, _start.jobMonitoringRun)({
      core,
      wazuh: {
        logger: this.logger.get('monitoring'),
        api: wazuhApiClient
      },
      server: contextServer
    }); // Scheduler

    (0, _start.jobSchedulerRun)({
      core,
      wazuh: {
        logger: this.logger.get('cron-scheduler'),
        api: wazuhApiClient
      },
      server: contextServer
    }); // Queue

    (0, _start.jobQueueRun)({
      core,
      wazuh: {
        logger: this.logger.get('queue'),
        api: wazuhApiClient
      },
      server: contextServer
    });
    return {};
  }

  stop() {}

}

exports.WazuhPlugin = WazuhPlugin;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInBsdWdpbi50cyJdLCJuYW1lcyI6WyJXYXp1aFBsdWdpbiIsImNvbnN0cnVjdG9yIiwiaW5pdGlhbGl6ZXJDb250ZXh0IiwibG9nZ2VyIiwiZ2V0Iiwic2V0dXAiLCJjb3JlIiwicGx1Z2lucyIsImRlYnVnIiwic2VydmVySW5mbyIsImh0dHAiLCJnZXRTZXJ2ZXJJbmZvIiwid2F6dWhTZWN1cml0eSIsInJlZ2lzdGVyUm91dGVIYW5kbGVyQ29udGV4dCIsImNvbnRleHQiLCJyZXF1ZXN0Iiwic2VydmVyIiwiaW5mbyIsInNlY3VyaXR5IiwiYXBpIiwiY2xpZW50IiwiYXNJbnRlcm5hbFVzZXIiLCJhdXRoZW50aWNhdGUiLCJhcGlIb3N0SUQiLCJBcGlJbnRlcmNlcHRvciIsIm1ldGhvZCIsInBhdGgiLCJkYXRhIiwib3B0aW9ucyIsInJlcXVlc3RBc0ludGVybmFsVXNlciIsImFzQ3VycmVudFVzZXIiLCJnZXRDdXJyZW50VXNlciIsImF1dGhDb250ZXh0IiwicmVxdWVzdEFzQ3VycmVudFVzZXIiLCJ0b2tlbiIsImhlYWRlcnMiLCJjb29raWUiLCJyZWdpc3Rlck9uUHJlUmVzcG9uc2UiLCJyZXNwb25zZSIsInRvb2xraXQiLCJhZGRpdGlvbmFsSGVhZGVycyIsIm5leHQiLCJyb3V0ZXIiLCJjcmVhdGVSb3V0ZXIiLCJzdGFydCIsImdsb2JhbENvbmZpZ3VyYXRpb24iLCJjb25maWciLCJsZWdhY3kiLCJnbG9iYWxDb25maWckIiwicGlwZSIsInRvUHJvbWlzZSIsIndhenVoQXBpQ2xpZW50IiwiY29udGV4dFNlcnZlciIsIndhenVoIiwic3RvcCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7QUE2QkE7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBR0E7Ozs7OztBQXBDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUEyQ08sTUFBTUEsV0FB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QyxNQUFBQSxJQURlO0FBRWYrQyxNQUFBQSxLQUFLLEVBQUU7QUFDTGxELFFBQUFBLE1BQU0sRUFBRSxLQUFLQSxNQUFMLENBQVlDLEdBQVosQ0FBZ0IsWUFBaEIsQ0FESDtBQUVMZSxRQUFBQSxHQUFHLEVBQUVnQztBQUZBLE9BRlE7QUFNZm5DLE1BQUFBLE1BQU0sRUFBRW9DO0FBTk8sS0FBakIsRUFwQ2tDLENBNkNsQzs7QUFDQSxnQ0FBZ0I7QUFDZDlDLE1BQUFBLElBRGM7QUFFZCtDLE1BQUFBLEtBQUssRUFBRTtBQUNMbEQsUUFBQUEsTUFBTSxFQUFFLEtBQUtBLE1BQUwsQ0FBWUMsR0FBWixDQUFnQixnQkFBaEIsQ0FESDtBQUVMZSxRQUFBQSxHQUFHLEVBQUVnQztBQUZBLE9BRk87QUFNZG5DLE1BQUFBLE1BQU0sRUFBRW9DO0FBTk0sS0FBaEIsRUE5Q2tDLENBdURsQzs7QUFDQSw0QkFBWTtBQUNWOUMsTUFBQUEsSUFEVTtBQUVWK0MsTUFBQUEsS0FBSyxFQUFFO0FBQ0xsRCxRQUFBQSxNQUFNLEVBQUUsS0FBS0EsTUFBTCxDQUFZQyxHQUFaLENBQWdCLE9BQWhCLENBREg7QUFFTGUsUUFBQUEsR0FBRyxFQUFFZ0M7QUFGQSxPQUZHO0FBTVZuQyxNQUFBQSxNQUFNLEVBQUVvQztBQU5FLEtBQVo7QUFRQSxXQUFPLEVBQVA7QUFDRDs7QUFFTUUsRUFBQUEsSUFBSSxHQUFHLENBQUc7O0FBdkg0RCIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBMaWNlbnNlZCB0byBFbGFzdGljc2VhcmNoIEIuVi4gdW5kZXIgb25lIG9yIG1vcmUgY29udHJpYnV0b3JcbiAqIGxpY2Vuc2UgYWdyZWVtZW50cy4gU2VlIHRoZSBOT1RJQ0UgZmlsZSBkaXN0cmlidXRlZCB3aXRoXG4gKiB0aGlzIHdvcmsgZm9yIGFkZGl0aW9uYWwgaW5mb3JtYXRpb24gcmVnYXJkaW5nIGNvcHlyaWdodFxuICogb3duZXJzaGlwLiBFbGFzdGljc2VhcmNoIEIuVi4gbGljZW5zZXMgdGhpcyBmaWxlIHRvIHlvdSB1bmRlclxuICogdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTsgeW91IG1heVxuICogbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbiAqIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuICpcbiAqICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuICpcbiAqIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZyxcbiAqIHNvZnR3YXJlIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuXG4gKiBcIkFTIElTXCIgQkFTSVMsIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWVxuICogS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4gIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlXG4gKiBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kIGxpbWl0YXRpb25zXG4gKiB1bmRlciB0aGUgTGljZW5zZS5cbiAqL1xuXG5pbXBvcnQge1xuICBDb3JlU2V0dXAsXG4gIENvcmVTdGFydCxcbiAgTG9nZ2VyLFxuICBQbHVnaW4sXG4gIFBsdWdpbkluaXRpYWxpemVyQ29udGV4dCxcbiAgU2hhcmVkR2xvYmFsQ29uZmlnXG59IGZyb20gJ2tpYmFuYS9zZXJ2ZXInO1xuXG5pbXBvcnQgeyBXYXp1aFBsdWdpblNldHVwLCBXYXp1aFBsdWdpblN0YXJ0LCBQbHVnaW5TZXR1cCB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgU2VjdXJpdHlPYmosIElTZWN1cml0eUZhY3RvcnkgfSBmcm9tICcuL2xpYi9zZWN1cml0eS1mYWN0b3J5JztcbmltcG9ydCB7IHNldHVwUm91dGVzIH0gZnJvbSAnLi9yb3V0ZXMnO1xuaW1wb3J0IHsgam9iSW5pdGlhbGl6ZVJ1biwgam9iTW9uaXRvcmluZ1J1biwgam9iU2NoZWR1bGVyUnVuLCBqb2JRdWV1ZVJ1biwgam9iTWlncmF0aW9uVGFza3NSdW4gfSBmcm9tICcuL3N0YXJ0JztcbmltcG9ydCB7IGdldENvb2tpZVZhbHVlQnlOYW1lIH0gZnJvbSAnLi9saWIvY29va2llJztcbmltcG9ydCAqIGFzIEFwaUludGVyY2VwdG9yICBmcm9tICcuL2xpYi9hcGktaW50ZXJjZXB0b3InO1xuaW1wb3J0IHsgc2NoZW1hLCBUeXBlT2YgfSBmcm9tICdAa2JuL2NvbmZpZy1zY2hlbWEnO1xuaW1wb3J0IHR5cGUgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgeyBmaXJzdCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcblxuZGVjbGFyZSBtb2R1bGUgJ2tpYmFuYS9zZXJ2ZXInIHtcbiAgaW50ZXJmYWNlIFJlcXVlc3RIYW5kbGVyQ29udGV4dCB7XG4gICAgd2F6dWg6IHtcbiAgICAgIGxvZ2dlcjogTG9nZ2VyLFxuICAgICAgcGx1Z2luczogUGx1Z2luU2V0dXAsXG4gICAgICBzZWN1cml0eTogSVNlY3VyaXR5RmFjdG9yeVxuICAgICAgYXBpOiB7XG4gICAgICAgIGNsaWVudDoge1xuICAgICAgICAgIGFzSW50ZXJuYWxVc2VyOiB7XG4gICAgICAgICAgICBhdXRoZW50aWNhdGU6IChhcGlIb3N0SUQ6IHN0cmluZykgPT4gUHJvbWlzZTxzdHJpbmc+XG4gICAgICAgICAgICByZXF1ZXN0OiAobWV0aG9kOiBzdHJpbmcsIHBhdGg6IHN0cmluZywgZGF0YTogYW55LCBvcHRpb25zOiB7YXBpSG9zdElEOiBzdHJpbmcsIGZvcmNlUmVmcmVzaD86Ym9vbGVhbn0pID0+IFByb21pc2U8YW55PlxuICAgICAgICAgIH0sXG4gICAgICAgICAgYXNDdXJyZW50VXNlcjoge1xuICAgICAgICAgICAgYXV0aGVudGljYXRlOiAoYXBpSG9zdElEOiBzdHJpbmcpID0+IFByb21pc2U8c3RyaW5nPlxuICAgICAgICAgICAgcmVxdWVzdDogKG1ldGhvZDogc3RyaW5nLCBwYXRoOiBzdHJpbmcsIGRhdGE6IGFueSwgb3B0aW9uczoge2FwaUhvc3RJRDogc3RyaW5nLCBmb3JjZVJlZnJlc2g/OmJvb2xlYW59KSA9PiBQcm9taXNlPGFueT5cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9O1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBXYXp1aFBsdWdpbiBpbXBsZW1lbnRzIFBsdWdpbjxXYXp1aFBsdWdpblNldHVwLCBXYXp1aFBsdWdpblN0YXJ0PiB7XG4gIHByaXZhdGUgcmVhZG9ubHkgbG9nZ2VyOiBMb2dnZXI7XG5cbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBpbml0aWFsaXplckNvbnRleHQ6IFBsdWdpbkluaXRpYWxpemVyQ29udGV4dCkge1xuICAgIHRoaXMubG9nZ2VyID0gaW5pdGlhbGl6ZXJDb250ZXh0LmxvZ2dlci5nZXQoKTtcbiAgfVxuXG4gIHB1YmxpYyBhc3luYyBzZXR1cChjb3JlOiBDb3JlU2V0dXAsIHBsdWdpbnM6IFBsdWdpblNldHVwKSB7XG4gICAgdGhpcy5sb2dnZXIuZGVidWcoJ1dhenVoLXd1aTogU2V0dXAnKTtcblxuICAgIGNvbnN0IHNlcnZlckluZm8gPSBjb3JlLmh0dHAuZ2V0U2VydmVySW5mbygpO1xuXG4gICAgbGV0IHdhenVoU2VjdXJpdHk7XG4gICAgY29yZS5odHRwLnJlZ2lzdGVyUm91dGVIYW5kbGVyQ29udGV4dCgnd2F6dWgnLCBhc3luYyhjb250ZXh0LCByZXF1ZXN0KSA9PiB7XG4gICAgICAhd2F6dWhTZWN1cml0eSAmJiAod2F6dWhTZWN1cml0eSA9IGF3YWl0IFNlY3VyaXR5T2JqKHBsdWdpbnMsIGNvbnRleHQpKTtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGxvZ2dlcjogdGhpcy5sb2dnZXIsXG4gICAgICAgIHNlcnZlcjoge1xuICAgICAgICAgIGluZm86IHNlcnZlckluZm8sIFxuICAgICAgICB9LFxuICAgICAgICBwbHVnaW5zLFxuICAgICAgICBzZWN1cml0eTogd2F6dWhTZWN1cml0eSxcbiAgICAgICAgYXBpOiB7XG4gICAgICAgICAgY2xpZW50OiB7XG4gICAgICAgICAgICBhc0ludGVybmFsVXNlcjoge1xuICAgICAgICAgICAgICBhdXRoZW50aWNhdGU6IGFzeW5jIChhcGlIb3N0SUQpID0+IGF3YWl0IEFwaUludGVyY2VwdG9yLmF1dGhlbnRpY2F0ZShhcGlIb3N0SUQpLFxuICAgICAgICAgICAgICByZXF1ZXN0OiBhc3luYyAobWV0aG9kLCBwYXRoLCBkYXRhLCBvcHRpb25zKSA9PiBhd2FpdCBBcGlJbnRlcmNlcHRvci5yZXF1ZXN0QXNJbnRlcm5hbFVzZXIobWV0aG9kLCBwYXRoLCBkYXRhLCBvcHRpb25zKSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBhc0N1cnJlbnRVc2VyOiB7XG4gICAgICAgICAgICAgIGF1dGhlbnRpY2F0ZTogYXN5bmMgKGFwaUhvc3RJRCkgPT4gYXdhaXQgQXBpSW50ZXJjZXB0b3IuYXV0aGVudGljYXRlKGFwaUhvc3RJRCwgKGF3YWl0IHdhenVoU2VjdXJpdHkuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCwgY29udGV4dCkpLmF1dGhDb250ZXh0KSxcbiAgICAgICAgICAgICAgcmVxdWVzdDogYXN5bmMgKG1ldGhvZCwgcGF0aCwgZGF0YSwgb3B0aW9ucykgPT4gYXdhaXQgQXBpSW50ZXJjZXB0b3IucmVxdWVzdEFzQ3VycmVudFVzZXIobWV0aG9kLCBwYXRoLCBkYXRhLCB7Li4ub3B0aW9ucywgdG9rZW46IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsICd3ei10b2tlbicpfSksXG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9O1xuICAgIH0pO1xuXG4gICAgLy8gQWRkIGN1c3RvbSBoZWFkZXJzIHRvIHRoZSByZXNwb25zZXNcbiAgICBjb3JlLmh0dHAucmVnaXN0ZXJPblByZVJlc3BvbnNlKChyZXF1ZXN0LCByZXNwb25zZSwgdG9vbGtpdCkgPT4ge1xuICAgICAgY29uc3QgYWRkaXRpb25hbEhlYWRlcnMgPSB7XG4gICAgICAgICd4LWZyYW1lLW9wdGlvbnMnOiAnc2FtZW9yaWdpbicsXG4gICAgICB9O1xuICAgICAgcmV0dXJuIHRvb2xraXQubmV4dCh7IGhlYWRlcnM6IGFkZGl0aW9uYWxIZWFkZXJzIH0pO1xuICAgIH0pO1xuXG4gICAgLy8gUm91dGVzXG4gICAgY29uc3Qgcm91dGVyID0gY29yZS5odHRwLmNyZWF0ZVJvdXRlcigpO1xuICAgIHNldHVwUm91dGVzKHJvdXRlcik7XG5cbiAgICByZXR1cm4ge307XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgc3RhcnQoY29yZTogQ29yZVN0YXJ0KSB7XG4gICAgY29uc3QgZ2xvYmFsQ29uZmlndXJhdGlvbjogU2hhcmVkR2xvYmFsQ29uZmlnID0gYXdhaXQgdGhpcy5pbml0aWFsaXplckNvbnRleHQuY29uZmlnLmxlZ2FjeS5nbG9iYWxDb25maWckLnBpcGUoZmlyc3QoKSkudG9Qcm9taXNlKCk7XG4gICAgY29uc3Qgd2F6dWhBcGlDbGllbnQgPSB7XG4gICAgICBjbGllbnQ6IHtcbiAgICAgICAgYXNJbnRlcm5hbFVzZXI6IHtcbiAgICAgICAgICBhdXRoZW50aWNhdGU6IGFzeW5jIChhcGlIb3N0SUQpID0+IGF3YWl0IEFwaUludGVyY2VwdG9yLmF1dGhlbnRpY2F0ZShhcGlIb3N0SUQpLFxuICAgICAgICAgIHJlcXVlc3Q6IGFzeW5jIChtZXRob2QsIHBhdGgsIGRhdGEsIG9wdGlvbnMpID0+IGF3YWl0IEFwaUludGVyY2VwdG9yLnJlcXVlc3RBc0ludGVybmFsVXNlcihtZXRob2QsIHBhdGgsIGRhdGEsIG9wdGlvbnMpLFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfTtcblxuICAgIGNvbnN0IGNvbnRleHRTZXJ2ZXIgPSB7XG4gICAgICBjb25maWc6IGdsb2JhbENvbmZpZ3VyYXRpb25cbiAgICB9O1xuXG4gICAgLy8gSW5pdGlhbGl6ZVxuICAgIGpvYkluaXRpYWxpemVSdW4oe1xuICAgICAgY29yZSwgXG4gICAgICB3YXp1aDoge1xuICAgICAgICBsb2dnZXI6IHRoaXMubG9nZ2VyLmdldCgnaW5pdGlhbGl6ZScpLFxuICAgICAgICBhcGk6IHdhenVoQXBpQ2xpZW50XG4gICAgICB9LFxuICAgICAgc2VydmVyOiBjb250ZXh0U2VydmVyXG4gICAgfSk7XG5cbiAgICAvLyBNaWdyYXRpb24gdGFza3NcbiAgICBqb2JNaWdyYXRpb25UYXNrc1J1bih7XG4gICAgICBjb3JlLCBcbiAgICAgIHdhenVoOiB7XG4gICAgICAgIGxvZ2dlcjogdGhpcy5sb2dnZXIuZ2V0KCdtaWdyYXRpb24tdGFzaycpLFxuICAgICAgICBhcGk6IHdhenVoQXBpQ2xpZW50XG4gICAgICB9LFxuICAgICAgc2VydmVyOiBjb250ZXh0U2VydmVyXG4gICAgfSk7XG5cbiAgICAvLyBNb25pdG9yaW5nXG4gICAgam9iTW9uaXRvcmluZ1J1bih7XG4gICAgICBjb3JlLFxuICAgICAgd2F6dWg6IHtcbiAgICAgICAgbG9nZ2VyOiB0aGlzLmxvZ2dlci5nZXQoJ21vbml0b3JpbmcnKSxcbiAgICAgICAgYXBpOiB3YXp1aEFwaUNsaWVudFxuICAgICAgfSxcbiAgICAgIHNlcnZlcjogY29udGV4dFNlcnZlclxuICAgIH0pO1xuXG4gICAgLy8gU2NoZWR1bGVyXG4gICAgam9iU2NoZWR1bGVyUnVuKHtcbiAgICAgIGNvcmUsXG4gICAgICB3YXp1aDoge1xuICAgICAgICBsb2dnZXI6IHRoaXMubG9nZ2VyLmdldCgnY3Jvbi1zY2hlZHVsZXInKSxcbiAgICAgICAgYXBpOiB3YXp1aEFwaUNsaWVudFxuICAgICAgfSxcbiAgICAgIHNlcnZlcjogY29udGV4dFNlcnZlclxuICAgIH0pO1xuXG4gICAgLy8gUXVldWVcbiAgICBqb2JRdWV1ZVJ1bih7XG4gICAgICBjb3JlLCBcbiAgICAgIHdhenVoOiB7XG4gICAgICAgIGxvZ2dlcjogdGhpcy5sb2dnZXIuZ2V0KCdxdWV1ZScpLFxuICAgICAgICBhcGk6IHdhenVoQXBpQ2xpZW50XG4gICAgICB9LFxuICAgICAgc2VydmVyOiBjb250ZXh0U2VydmVyXG4gICAgfSk7XG4gICAgcmV0dXJuIHt9O1xuICB9XG5cbiAgcHVibGljIHN0b3AoKSB7IH1cbn1cbiJdfQ==