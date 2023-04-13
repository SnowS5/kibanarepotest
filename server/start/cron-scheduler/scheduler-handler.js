"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.jobSchedulerRun = jobSchedulerRun;

var _index = require("./index");

var _configuredJobs = require("./configured-jobs");

var _logger = require("../../lib/logger");

var _getConfiguration = require("../../lib/get-configuration");

var _nodeCron = _interopRequireDefault(require("node-cron"));

var _constants = require("../../../common/constants");

var _statisticsTemplate = require("../../integration-files/statistics-template");

var _utils = require("../../../common/utils");

var _settings = require("../../../common/services/settings");

const blueWazuh = '\u001b[34mwazuh\u001b[39m';
const schedulerErrorLogColors = [blueWazuh, 'scheduler', 'error'];
const schedulerJobs = [];
/**
* Wait until Kibana server is ready
*/

const checkPluginPlatformStatus = async function (context) {
  try {
    (0, _logger.log)('scheduler-handler:checkPluginPlatformStatus', 'Waiting for Kibana and Elasticsearch servers to be ready...', 'debug');
    await checkElasticsearchServer(context);
    await checkTemplate(context);
    return;
  } catch (error) {
    (0, _logger.log)('scheduler-handler:checkPluginPlatformStatus', error.mesage || error);

    try {
      await (0, _utils.delayAsPromise)(3000);
      await checkPluginPlatformStatus(context);
    } catch (error) {}

    ;
  }
};
/**
 * Check Elasticsearch Server status and Kibana index presence
 */


const checkElasticsearchServer = async function (context) {
  try {
    const data = await context.core.elasticsearch.client.asInternalUser.indices.exists({
      index: context.server.config.kibana.index
    });
    return data.body;
  } catch (error) {
    (0, _logger.log)('scheduler-handler:checkElasticsearchServer', error.message || error);
    return Promise.reject(error);
  }
};
/**
* Verify wazuh-statistics template
*/


const checkTemplate = async function (context) {
  try {
    (0, _logger.log)('scheduler-handler:checkTemplate', 'Updating the statistics template', 'debug');
    const appConfig = await (0, _getConfiguration.getConfiguration)();
    const prefixTemplateName = appConfig['cron.prefix'] || (0, _settings.getSettingDefaultValue)('cron.prefix');
    const statisticsIndicesTemplateName = appConfig['cron.statistics.index.name'] || (0, _settings.getSettingDefaultValue)('cron.statistics.index.name');
    const pattern = `${prefixTemplateName}-${statisticsIndicesTemplateName}-*`;

    try {
      // Check if the template already exists
      const currentTemplate = await context.core.elasticsearch.client.asInternalUser.indices.getTemplate({
        name: _constants.WAZUH_STATISTICS_TEMPLATE_NAME
      }); // Copy already created index patterns

      _statisticsTemplate.statisticsTemplate.index_patterns = currentTemplate.body[_constants.WAZUH_STATISTICS_TEMPLATE_NAME].index_patterns;
    } catch (error) {
      // Init with the default index pattern
      _statisticsTemplate.statisticsTemplate.index_patterns = [pattern];
    } // Check if the user is using a custom pattern and add it to the template if it does


    if (!_statisticsTemplate.statisticsTemplate.index_patterns.includes(pattern)) {
      _statisticsTemplate.statisticsTemplate.index_patterns.push(pattern);
    }

    ; // Update the statistics template

    await context.core.elasticsearch.client.asInternalUser.indices.putTemplate({
      name: _constants.WAZUH_STATISTICS_TEMPLATE_NAME,
      body: _statisticsTemplate.statisticsTemplate
    });
    (0, _logger.log)('scheduler-handler:checkTemplate', 'Updated the statistics template', 'debug');
  } catch (error) {
    const errorMessage = `Something went wrong updating the statistics template ${error.message || error}`;
    (0, _logger.log)('scheduler-handler:checkTemplate', errorMessage);
    context.wazuh.logger.error(schedulerErrorLogColors, errorMessage);
    throw error;
  }
};

async function jobSchedulerRun(context) {
  // Check Kibana index and if it is prepared, start the initialization of Wazuh App.
  await checkPluginPlatformStatus(context);

  for (const job in (0, _configuredJobs.configuredJobs)({})) {
    const schedulerJob = new _index.SchedulerJob(job, context);
    schedulerJobs.push(schedulerJob);

    const task = _nodeCron.default.schedule(_index.jobs[job].interval, () => schedulerJob.run());
  }
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNjaGVkdWxlci1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbImJsdWVXYXp1aCIsInNjaGVkdWxlckVycm9yTG9nQ29sb3JzIiwic2NoZWR1bGVySm9icyIsImNoZWNrUGx1Z2luUGxhdGZvcm1TdGF0dXMiLCJjb250ZXh0IiwiY2hlY2tFbGFzdGljc2VhcmNoU2VydmVyIiwiY2hlY2tUZW1wbGF0ZSIsImVycm9yIiwibWVzYWdlIiwiZGF0YSIsImNvcmUiLCJlbGFzdGljc2VhcmNoIiwiY2xpZW50IiwiYXNJbnRlcm5hbFVzZXIiLCJpbmRpY2VzIiwiZXhpc3RzIiwiaW5kZXgiLCJzZXJ2ZXIiLCJjb25maWciLCJraWJhbmEiLCJib2R5IiwibWVzc2FnZSIsIlByb21pc2UiLCJyZWplY3QiLCJhcHBDb25maWciLCJwcmVmaXhUZW1wbGF0ZU5hbWUiLCJzdGF0aXN0aWNzSW5kaWNlc1RlbXBsYXRlTmFtZSIsInBhdHRlcm4iLCJjdXJyZW50VGVtcGxhdGUiLCJnZXRUZW1wbGF0ZSIsIm5hbWUiLCJXQVpVSF9TVEFUSVNUSUNTX1RFTVBMQVRFX05BTUUiLCJzdGF0aXN0aWNzVGVtcGxhdGUiLCJpbmRleF9wYXR0ZXJucyIsImluY2x1ZGVzIiwicHVzaCIsInB1dFRlbXBsYXRlIiwiZXJyb3JNZXNzYWdlIiwid2F6dWgiLCJsb2dnZXIiLCJqb2JTY2hlZHVsZXJSdW4iLCJqb2IiLCJzY2hlZHVsZXJKb2IiLCJTY2hlZHVsZXJKb2IiLCJ0YXNrIiwiY3JvbiIsInNjaGVkdWxlIiwiam9icyIsImludGVydmFsIiwicnVuIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFBQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFFQSxNQUFNQSxTQUFTLEdBQUcsMkJBQWxCO0FBQ0EsTUFBTUMsdUJBQXVCLEdBQUcsQ0FBQ0QsU0FBRCxFQUFZLFdBQVosRUFBeUIsT0FBekIsQ0FBaEM7QUFDQSxNQUFNRSxhQUFhLEdBQUcsRUFBdEI7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QUFBLElBQUksRUFBRVk7QUFGbUUsS0FBckUsQ0FBTjtBQUlBLHFCQUNFLGlDQURGLEVBRUUsaUNBRkYsRUFHRSxPQUhGO0FBS0QsR0F2Q0QsQ0F1Q0UsT0FBT3pCLEtBQVAsRUFBYztBQUNkLFVBQU04QixZQUFZLEdBQUkseURBQXdEOUIsS0FBSyxDQUFDYyxPQUFOLElBQWlCZCxLQUFNLEVBQXJHO0FBQ0EscUJBQ0UsaUNBREYsRUFFRThCLFlBRkY7QUFJQWpDLElBQUFBLE9BQU8sQ0FBQ2tDLEtBQVIsQ0FBY0MsTUFBZCxDQUFxQmhDLEtBQXJCLENBQTJCTix1QkFBM0IsRUFBb0RvQyxZQUFwRDtBQUNBLFVBQU05QixLQUFOO0FBQ0Q7QUFDRixDQWpERDs7QUFtRE8sZUFBZWlDLGVBQWYsQ0FBK0JwQyxPQUEvQixFQUF1QztBQUM1QztBQUNBLFFBQU1ELHlCQUF5QixDQUFDQyxPQUFELENBQS9COztBQUNBLE9BQUssTUFBTXFDLEdBQVgsSUFBa0Isb0NBQWUsRUFBZixDQUFsQixFQUFzQztBQUNwQyxVQUFNQyxZQUEwQixHQUFHLElBQUlDLG1CQUFKLENBQWlCRixHQUFqQixFQUFzQnJDLE9BQXRCLENBQW5DO0FBQ0FGLElBQUFBLGFBQWEsQ0FBQ2lDLElBQWQsQ0FBbUJPLFlBQW5COztBQUNBLFVBQU1FLElBQUksR0FBR0Msa0JBQUtDLFFBQUwsQ0FDWEMsWUFBS04sR0FBTCxFQUFVTyxRQURDLEVBRVgsTUFBTU4sWUFBWSxDQUFDTyxHQUFiLEVBRkssQ0FBYjtBQUlEO0FBQ0YiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBqb2JzLCBTY2hlZHVsZXJKb2IgfSBmcm9tICcuL2luZGV4JztcbmltcG9ydCB7IGNvbmZpZ3VyZWRKb2JzIH0gZnJvbSAnLi9jb25maWd1cmVkLWpvYnMnO1xuaW1wb3J0IHsgbG9nIH0gZnJvbSAnLi4vLi4vbGliL2xvZ2dlcic7XG5pbXBvcnQgeyBnZXRDb25maWd1cmF0aW9uIH0gZnJvbSAnLi4vLi4vbGliL2dldC1jb25maWd1cmF0aW9uJztcbmltcG9ydCBjcm9uIGZyb20gJ25vZGUtY3Jvbic7XG5pbXBvcnQgeyBXQVpVSF9TVEFUSVNUSUNTX1RFTVBMQVRFX05BTUUgfSBmcm9tICcuLi8uLi8uLi9jb21tb24vY29uc3RhbnRzJztcbmltcG9ydCB7IHN0YXRpc3RpY3NUZW1wbGF0ZSB9IGZyb20gJy4uLy4uL2ludGVncmF0aW9uLWZpbGVzL3N0YXRpc3RpY3MtdGVtcGxhdGUnO1xuaW1wb3J0IHsgZGVsYXlBc1Byb21pc2UgfSBmcm9tICcuLi8uLi8uLi9jb21tb24vdXRpbHMnO1xuaW1wb3J0IHsgZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9zZXJ2aWNlcy9zZXR0aW5ncyc7XG5cbmNvbnN0IGJsdWVXYXp1aCA9ICdcXHUwMDFiWzM0bXdhenVoXFx1MDAxYlszOW0nO1xuY29uc3Qgc2NoZWR1bGVyRXJyb3JMb2dDb2xvcnMgPSBbYmx1ZVdhenVoLCAnc2NoZWR1bGVyJywgJ2Vycm9yJ107XG5jb25zdCBzY2hlZHVsZXJKb2JzID0gW107XG5cbi8qKlxuKiBXYWl0IHVudGlsIEtpYmFuYSBzZXJ2ZXIgaXMgcmVhZHlcbiovXG5jb25zdCBjaGVja1BsdWdpblBsYXRmb3JtU3RhdHVzID0gYXN5bmMgZnVuY3Rpb24gKGNvbnRleHQpIHtcbiAgdHJ5IHtcbiAgICAgbG9nKFxuICAgICAgICdzY2hlZHVsZXItaGFuZGxlcjpjaGVja1BsdWdpblBsYXRmb3JtU3RhdHVzJyxcbiAgICAgICAnV2FpdGluZyBmb3IgS2liYW5hIGFuZCBFbGFzdGljc2VhcmNoIHNlcnZlcnMgdG8gYmUgcmVhZHkuLi4nLFxuICAgICAgICdkZWJ1ZydcbiAgICAgKTtcbiBcbiAgICBhd2FpdCBjaGVja0VsYXN0aWNzZWFyY2hTZXJ2ZXIoY29udGV4dCk7XG4gICAgYXdhaXQgY2hlY2tUZW1wbGF0ZShjb250ZXh0KTtcbiAgICByZXR1cm47XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgIGxvZyhcbiAgICAgICAnc2NoZWR1bGVyLWhhbmRsZXI6Y2hlY2tQbHVnaW5QbGF0Zm9ybVN0YXR1cycsXG4gICAgICAgZXJyb3IubWVzYWdlIHx8ZXJyb3JcbiAgICAgKTtcbiAgICAgdHJ5e1xuICAgICAgIGF3YWl0IGRlbGF5QXNQcm9taXNlKDMwMDApO1xuICAgICAgIGF3YWl0IGNoZWNrUGx1Z2luUGxhdGZvcm1TdGF0dXMoY29udGV4dCk7XG4gICAgIH1jYXRjaChlcnJvcil7fTtcbiAgfVxuIH1cbiBcbiBcbiAvKipcbiAgKiBDaGVjayBFbGFzdGljc2VhcmNoIFNlcnZlciBzdGF0dXMgYW5kIEtpYmFuYSBpbmRleCBwcmVzZW5jZVxuICAqL1xuIGNvbnN0IGNoZWNrRWxhc3RpY3NlYXJjaFNlcnZlciA9IGFzeW5jIGZ1bmN0aW9uIChjb250ZXh0KSB7XG4gICB0cnkge1xuICAgICBjb25zdCBkYXRhID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuZXhpc3RzKHtcbiAgICAgICBpbmRleDogY29udGV4dC5zZXJ2ZXIuY29uZmlnLmtpYmFuYS5pbmRleFxuICAgICB9KTtcbiBcbiAgICAgcmV0dXJuIGRhdGEuYm9keTtcbiAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgIGxvZygnc2NoZWR1bGVyLWhhbmRsZXI6Y2hlY2tFbGFzdGljc2VhcmNoU2VydmVyJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICB9XG4gfVxuXG5cbiAvKipcbiAqIFZlcmlmeSB3YXp1aC1zdGF0aXN0aWNzIHRlbXBsYXRlXG4gKi9cbmNvbnN0IGNoZWNrVGVtcGxhdGUgPSBhc3luYyBmdW5jdGlvbiAoY29udGV4dCkge1xuICB0cnkge1xuICAgIGxvZyhcbiAgICAgICdzY2hlZHVsZXItaGFuZGxlcjpjaGVja1RlbXBsYXRlJyxcbiAgICAgICdVcGRhdGluZyB0aGUgc3RhdGlzdGljcyB0ZW1wbGF0ZScsXG4gICAgICAnZGVidWcnXG4gICAgKTtcblxuICAgIGNvbnN0IGFwcENvbmZpZyA9IGF3YWl0IGdldENvbmZpZ3VyYXRpb24oKTtcbiAgICBjb25zdCBwcmVmaXhUZW1wbGF0ZU5hbWUgPSBhcHBDb25maWdbJ2Nyb24ucHJlZml4J10gfHwgZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSgnY3Jvbi5wcmVmaXgnKTtcbiAgICBjb25zdCBzdGF0aXN0aWNzSW5kaWNlc1RlbXBsYXRlTmFtZSA9IGFwcENvbmZpZ1snY3Jvbi5zdGF0aXN0aWNzLmluZGV4Lm5hbWUnXSB8fCBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCdjcm9uLnN0YXRpc3RpY3MuaW5kZXgubmFtZScpO1xuICAgIGNvbnN0IHBhdHRlcm4gPSBgJHtwcmVmaXhUZW1wbGF0ZU5hbWV9LSR7c3RhdGlzdGljc0luZGljZXNUZW1wbGF0ZU5hbWV9LSpgO1xuXG4gICAgdHJ5IHtcbiAgICAgIC8vIENoZWNrIGlmIHRoZSB0ZW1wbGF0ZSBhbHJlYWR5IGV4aXN0c1xuICAgICAgY29uc3QgY3VycmVudFRlbXBsYXRlID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuZ2V0VGVtcGxhdGUoe1xuICAgICAgICBuYW1lOiBXQVpVSF9TVEFUSVNUSUNTX1RFTVBMQVRFX05BTUVcbiAgICAgIH0pO1xuICAgICAgLy8gQ29weSBhbHJlYWR5IGNyZWF0ZWQgaW5kZXggcGF0dGVybnNcbiAgICAgIHN0YXRpc3RpY3NUZW1wbGF0ZS5pbmRleF9wYXR0ZXJucyA9IGN1cnJlbnRUZW1wbGF0ZS5ib2R5W1dBWlVIX1NUQVRJU1RJQ1NfVEVNUExBVEVfTkFNRV0uaW5kZXhfcGF0dGVybnM7XG4gICAgfWNhdGNoIChlcnJvcikge1xuICAgICAgLy8gSW5pdCB3aXRoIHRoZSBkZWZhdWx0IGluZGV4IHBhdHRlcm5cbiAgICAgIHN0YXRpc3RpY3NUZW1wbGF0ZS5pbmRleF9wYXR0ZXJucyA9IFtwYXR0ZXJuXTtcbiAgICB9XG5cbiAgICAvLyBDaGVjayBpZiB0aGUgdXNlciBpcyB1c2luZyBhIGN1c3RvbSBwYXR0ZXJuIGFuZCBhZGQgaXQgdG8gdGhlIHRlbXBsYXRlIGlmIGl0IGRvZXNcbiAgICBpZiAoIXN0YXRpc3RpY3NUZW1wbGF0ZS5pbmRleF9wYXR0ZXJucy5pbmNsdWRlcyhwYXR0ZXJuKSkge1xuICAgICAgc3RhdGlzdGljc1RlbXBsYXRlLmluZGV4X3BhdHRlcm5zLnB1c2gocGF0dGVybik7XG4gICAgfTtcblxuICAgIC8vIFVwZGF0ZSB0aGUgc3RhdGlzdGljcyB0ZW1wbGF0ZVxuICAgIGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5pbmRpY2VzLnB1dFRlbXBsYXRlKHtcbiAgICAgIG5hbWU6IFdBWlVIX1NUQVRJU1RJQ1NfVEVNUExBVEVfTkFNRSxcbiAgICAgIGJvZHk6IHN0YXRpc3RpY3NUZW1wbGF0ZVxuICAgIH0pO1xuICAgIGxvZyhcbiAgICAgICdzY2hlZHVsZXItaGFuZGxlcjpjaGVja1RlbXBsYXRlJyxcbiAgICAgICdVcGRhdGVkIHRoZSBzdGF0aXN0aWNzIHRlbXBsYXRlJyxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGNvbnN0IGVycm9yTWVzc2FnZSA9IGBTb21ldGhpbmcgd2VudCB3cm9uZyB1cGRhdGluZyB0aGUgc3RhdGlzdGljcyB0ZW1wbGF0ZSAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YDtcbiAgICBsb2coXG4gICAgICAnc2NoZWR1bGVyLWhhbmRsZXI6Y2hlY2tUZW1wbGF0ZScsXG4gICAgICBlcnJvck1lc3NhZ2VcbiAgICApO1xuICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKHNjaGVkdWxlckVycm9yTG9nQ29sb3JzLCBlcnJvck1lc3NhZ2UpO1xuICAgIHRocm93IGVycm9yO1xuICB9XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBqb2JTY2hlZHVsZXJSdW4oY29udGV4dCl7XG4gIC8vIENoZWNrIEtpYmFuYSBpbmRleCBhbmQgaWYgaXQgaXMgcHJlcGFyZWQsIHN0YXJ0IHRoZSBpbml0aWFsaXphdGlvbiBvZiBXYXp1aCBBcHAuXG4gIGF3YWl0IGNoZWNrUGx1Z2luUGxhdGZvcm1TdGF0dXMoY29udGV4dCk7XG4gIGZvciAoY29uc3Qgam9iIGluIGNvbmZpZ3VyZWRKb2JzKHt9KSkge1xuICAgIGNvbnN0IHNjaGVkdWxlckpvYjogU2NoZWR1bGVySm9iID0gbmV3IFNjaGVkdWxlckpvYihqb2IsIGNvbnRleHQpO1xuICAgIHNjaGVkdWxlckpvYnMucHVzaChzY2hlZHVsZXJKb2IpO1xuICAgIGNvbnN0IHRhc2sgPSBjcm9uLnNjaGVkdWxlKFxuICAgICAgam9ic1tqb2JdLmludGVydmFsLFxuICAgICAgKCkgPT4gc2NoZWR1bGVySm9iLnJ1bigpLFxuICAgICk7XG4gIH1cbn0iXX0=