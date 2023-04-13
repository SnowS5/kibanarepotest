"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhApiRoutes = WazuhApiRoutes;

var _controllers = require("../controllers");

var _configSchema = require("@kbn/config-schema");

function WazuhApiRoutes(router) {
  const ctrl = new _controllers.WazuhApiCtrl(); // Returns if the wazuh-api configuration is working

  router.post({
    path: '/api/check-stored-api',
    validate: {
      body: _configSchema.schema.object({
        id: _configSchema.schema.string(),
        idChanged: _configSchema.schema.maybe(_configSchema.schema.string())
      })
    }
  }, async (context, request, response) => ctrl.checkStoredAPI(context, request, response)); // Check if credentials on POST connect to Wazuh API. Not storing them!
  // Returns if the wazuh-api configuration received in the POST body will work

  router.post({
    path: '/api/check-api',
    validate: {
      body: _configSchema.schema.any({// TODO: not ready
        //id: schema.string(),
        // url: schema.string(),
        // port: schema.number(),
        // username: schema.string(),
        //forceRefresh: schema.boolean({defaultValue:false}),
        // cluster_info: schema.object({
        //   status: schema.string(),
        //   manager: schema.string(),
        //   node: schema.string(),
        //   cluster: schema.string()
        // }),
        // run_as: schema.boolean(),
        // extensions: schema.any(),
        // allow_run_as: schema.number()
      })
    }
  }, async (context, request, response) => ctrl.checkAPI(context, request, response));
  router.post({
    path: '/api/login',
    validate: {
      body: _configSchema.schema.object({
        idHost: _configSchema.schema.string(),
        force: _configSchema.schema.boolean({
          defaultValue: false
        })
      })
    }
  }, async (context, request, response) => ctrl.getToken(context, request, response)); // Returns the request result (With error control)

  router.post({
    path: '/api/request',
    validate: {
      body: _configSchema.schema.object({
        id: _configSchema.schema.string(),
        method: _configSchema.schema.string(),
        path: _configSchema.schema.string(),
        body: _configSchema.schema.any()
      })
    }
  }, async (context, request, response) => ctrl.requestApi(context, request, response)); // Returns data from the Wazuh API on CSV readable format

  router.post({
    path: '/api/csv',
    validate: {
      body: _configSchema.schema.object({
        id: _configSchema.schema.string(),
        path: _configSchema.schema.string(),
        filters: _configSchema.schema.maybe(_configSchema.schema.any())
      })
    }
  }, async (context, request, response) => ctrl.csv(context, request, response)); // Returns a route list used by the Dev Tools

  router.get({
    path: '/api/routes',
    validate: false
  }, async (context, request, response) => ctrl.getRequestList(context, request, response)); // Useful to check cookie consistence

  router.get({
    path: '/api/timestamp',
    validate: false
  }, async (context, request, response) => ctrl.getTimeStamp(context, request, response));
  router.post({
    path: '/api/extensions',
    validate: {
      body: _configSchema.schema.object({
        id: _configSchema.schema.string(),
        extensions: _configSchema.schema.any()
      })
    }
  }, async (context, request, response) => ctrl.setExtensions(context, request, response));
  router.get({
    path: '/api/extensions/{id}',
    validate: {
      params: _configSchema.schema.object({
        id: _configSchema.schema.string()
      })
    }
  }, async (context, request, response) => ctrl.getExtensions(context, request, response)); // Return Wazuh Appsetup info

  router.get({
    path: '/api/setup',
    validate: false
  }, async (context, request, response) => ctrl.getSetupInfo(context, request, response)); // Return basic information of syscollector for given agent

  router.get({
    path: '/api/syscollector/{agent}',
    validate: {
      params: _configSchema.schema.object({
        agent: _configSchema.schema.string()
      })
    }
  }, async (context, request, response) => ctrl.getSyscollector(context, request, response)); // Return logged in user has wazuh disabled by role

  router.get({
    path: '/api/check-wazuh',
    validate: false
  }, async (context, request, response) => ctrl.isWazuhDisabled(context, request, response)); // Return app logos configuration

  router.get({
    path: '/api/logos',
    validate: false,
    options: {
      authRequired: false
    }
  }, async (context, request, response) => ctrl.getAppLogos(context, request, response));
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLWFwaS50cyJdLCJuYW1lcyI6WyJXYXp1aEFwaVJvdXRlcyIsInJvdXRlciIsImN0cmwiLCJXYXp1aEFwaUN0cmwiLCJwb3N0IiwicGF0aCIsInZhbGlkYXRlIiwiYm9keSIsInNjaGVtYSIsIm9iamVjdCIsImlkIiwic3RyaW5nIiwiaWRDaGFuZ2VkIiwibWF5YmUiLCJjb250ZXh0IiwicmVxdWVzdCIsInJlc3BvbnNlIiwiY2hlY2tTdG9yZWRBUEkiLCJhbnkiLCJjaGVja0FQSSIsImlkSG9zdCIsImZvcmNlIiwiYm9vbGVhbiIsImRlZmF1bHRWYWx1ZSIsImdldFRva2VuIiwibWV0aG9kIiwicmVxdWVzdEFwaSIsImZpbHRlcnMiLCJjc3YiLCJnZXQiLCJnZXRSZXF1ZXN0TGlzdCIsImdldFRpbWVTdGFtcCIsImV4dGVuc2lvbnMiLCJzZXRFeHRlbnNpb25zIiwicGFyYW1zIiwiZ2V0RXh0ZW5zaW9ucyIsImdldFNldHVwSW5mbyIsImFnZW50IiwiZ2V0U3lzY29sbGVjdG9yIiwiaXNXYXp1aERpc2FibGVkIiwib3B0aW9ucyIsImF1dGhSZXF1aXJlZCIsImdldEFwcExvZ29zIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBRUE7O0FBQ0E7O0FBRU8sU0FBU0EsY0FBVCxDQUF3QkMsTUFBeEIsRUFBeUM7QUFDOUMsUUFBTUMsSUFBSSxHQUFHLElBQUlDLHlCQUFKLEVBQWIsQ0FEOEMsQ0FHOUM7O0FBQ0FGLEVBQUFBLE1BQU0sQ0FBQ0csSUFBUCxDQUFZO0FBQ1ZDLElBQUFBLElBQUksRUFBRSx1QkFESTtBQUVWQyxJQUFBQSxRQUFRLEVBQUU7QUFDUkMsTUFBQUEsSUFBSSxFQUFFQyxxQkFBT0MsTUFBUCxDQUFjO0FBQ2xCQyxRQUFBQSxFQUFFLEVBQUVGLHFCQUFPRyxNQUFQLEVBRGM7QUFFbEJDLFFBQUFBLFNBQVMsRUFBRUoscUJBQU9LLEtBQVAsQ0FBYUwscUJBQU9HLE1BQVAsRUFBYjtBQUZPLE9BQWQ7QUFERTtBQUZBLEdBQVosRUFTRSxP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QyxJQUFBQSxRQUFRLEVBQUUsS0FGRDtBQUdUa0MsSUFBQUEsT0FBTyxFQUFFO0FBQUVDLE1BQUFBLFlBQVksRUFBRTtBQUFoQjtBQUhBLEdBQVgsRUFLRSxPQUFPM0IsT0FBUCxFQUFnQkMsT0FBaEIsRUFBeUJDLFFBQXpCLEtBQXNDZCxJQUFJLENBQUN3QyxXQUFMLENBQWlCNUIsT0FBakIsRUFBMEJDLE9BQTFCLEVBQW1DQyxRQUFuQyxDQUx4QztBQU9EIiwic291cmNlc0NvbnRlbnQiOlsiXG5pbXBvcnQgeyBJUm91dGVyIH0gZnJvbSAna2liYW5hL3NlcnZlcic7XG5pbXBvcnQgeyBXYXp1aEFwaUN0cmwgfSBmcm9tICcuLi9jb250cm9sbGVycyc7XG5pbXBvcnQgeyBzY2hlbWEgfSBmcm9tICdAa2JuL2NvbmZpZy1zY2hlbWEnO1xuXG5leHBvcnQgZnVuY3Rpb24gV2F6dWhBcGlSb3V0ZXMocm91dGVyOiBJUm91dGVyKSB7XG4gIGNvbnN0IGN0cmwgPSBuZXcgV2F6dWhBcGlDdHJsKCk7XG5cbiAgLy8gUmV0dXJucyBpZiB0aGUgd2F6dWgtYXBpIGNvbmZpZ3VyYXRpb24gaXMgd29ya2luZ1xuICByb3V0ZXIucG9zdCh7XG4gICAgcGF0aDogJy9hcGkvY2hlY2stc3RvcmVkLWFwaScsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGJvZHk6IHNjaGVtYS5vYmplY3Qoe1xuICAgICAgICBpZDogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICBpZENoYW5nZWQ6IHNjaGVtYS5tYXliZShzY2hlbWEuc3RyaW5nKCkpXG4gICAgICB9KVxuICAgIH1cbiAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwuY2hlY2tTdG9yZWRBUEkoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpXG4gICk7XG5cbiAgLy8gQ2hlY2sgaWYgY3JlZGVudGlhbHMgb24gUE9TVCBjb25uZWN0IHRvIFdhenVoIEFQSS4gTm90IHN0b3JpbmcgdGhlbSFcbiAgLy8gUmV0dXJucyBpZiB0aGUgd2F6dWgtYXBpIGNvbmZpZ3VyYXRpb24gcmVjZWl2ZWQgaW4gdGhlIFBPU1QgYm9keSB3aWxsIHdvcmtcbiAgcm91dGVyLnBvc3Qoe1xuICAgIHBhdGg6ICcvYXBpL2NoZWNrLWFwaScsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGJvZHk6IHNjaGVtYS5hbnkoeyAvLyBUT0RPOiBub3QgcmVhZHlcbiAgICAgICAgLy9pZDogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICAvLyB1cmw6IHNjaGVtYS5zdHJpbmcoKSxcbiAgICAgICAgLy8gcG9ydDogc2NoZW1hLm51bWJlcigpLFxuICAgICAgICAvLyB1c2VybmFtZTogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICAvL2ZvcmNlUmVmcmVzaDogc2NoZW1hLmJvb2xlYW4oe2RlZmF1bHRWYWx1ZTpmYWxzZX0pLFxuICAgICAgICAvLyBjbHVzdGVyX2luZm86IHNjaGVtYS5vYmplY3Qoe1xuICAgICAgICAvLyAgIHN0YXR1czogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICAvLyAgIG1hbmFnZXI6IHNjaGVtYS5zdHJpbmcoKSxcbiAgICAgICAgLy8gICBub2RlOiBzY2hlbWEuc3RyaW5nKCksXG4gICAgICAgIC8vICAgY2x1c3Rlcjogc2NoZW1hLnN0cmluZygpXG4gICAgICAgIC8vIH0pLFxuICAgICAgICAvLyBydW5fYXM6IHNjaGVtYS5ib29sZWFuKCksXG4gICAgICAgIC8vIGV4dGVuc2lvbnM6IHNjaGVtYS5hbnkoKSxcbiAgICAgICAgLy8gYWxsb3dfcnVuX2FzOiBzY2hlbWEubnVtYmVyKClcbiAgICAgIH0pXG4gICAgfVxuICB9LFxuICAgIGFzeW5jIChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSkgPT4gY3RybC5jaGVja0FQSShjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICByb3V0ZXIucG9zdCh7XG4gICAgcGF0aDogJy9hcGkvbG9naW4nLFxuICAgIHZhbGlkYXRlOiB7XG4gICAgICBib2R5OiBzY2hlbWEub2JqZWN0KHtcbiAgICAgICAgaWRIb3N0OiBzY2hlbWEuc3RyaW5nKCksXG4gICAgICAgIGZvcmNlOiBzY2hlbWEuYm9vbGVhbih7ZGVmYXVsdFZhbHVlOiBmYWxzZX0pLFxuICAgICAgfSlcbiAgICB9XG4gIH0sXG4gICAgYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiBjdHJsLmdldFRva2VuKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKVxuICApO1xuXG4gIC8vIFJldHVybnMgdGhlIHJlcXVlc3QgcmVzdWx0IChXaXRoIGVycm9yIGNvbnRyb2wpXG4gIHJvdXRlci5wb3N0KHtcbiAgICBwYXRoOiAnL2FwaS9yZXF1ZXN0JyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgYm9keTogc2NoZW1hLm9iamVjdCh7XG4gICAgICAgIGlkOiBzY2hlbWEuc3RyaW5nKCksXG4gICAgICAgIG1ldGhvZDogc2NoZW1hLnN0cmluZygpLFxuICAgICAgICBwYXRoOiBzY2hlbWEuc3RyaW5nKCksXG4gICAgICAgIGJvZHk6IHNjaGVtYS5hbnkoKSxcbiAgICAgIH0pXG4gICAgfVxuICB9LFxuICAgIGFzeW5jIChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSkgPT4gY3RybC5yZXF1ZXN0QXBpKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKVxuICApO1xuXG4gIC8vIFJldHVybnMgZGF0YSBmcm9tIHRoZSBXYXp1aCBBUEkgb24gQ1NWIHJlYWRhYmxlIGZvcm1hdFxuICByb3V0ZXIucG9zdCh7XG4gICAgcGF0aDogJy9hcGkvY3N2JyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgYm9keTogc2NoZW1hLm9iamVjdCh7XG4gICAgICAgIGlkOiBzY2hlbWEuc3RyaW5nKCksXG4gICAgICAgIHBhdGg6IHNjaGVtYS5zdHJpbmcoKSxcbiAgICAgICAgZmlsdGVyczogc2NoZW1hLm1heWJlKHNjaGVtYS5hbnkoKSlcbiAgICAgIH0pXG4gICAgfVxuICB9LFxuICAgIGFzeW5jIChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSkgPT4gY3RybC5jc3YoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpXG4gICk7XG5cbiAgLy8gUmV0dXJucyBhIHJvdXRlIGxpc3QgdXNlZCBieSB0aGUgRGV2IFRvb2xzXG4gIHJvdXRlci5nZXQoe1xuICAgIHBhdGg6ICcvYXBpL3JvdXRlcycsXG4gICAgdmFsaWRhdGU6IGZhbHNlXG4gIH0sXG4gICAgYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiBjdHJsLmdldFJlcXVlc3RMaXN0KGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKVxuICApO1xuXG4gIC8vIFVzZWZ1bCB0byBjaGVjayBjb29raWUgY29uc2lzdGVuY2VcbiAgcm91dGVyLmdldCh7XG4gICAgcGF0aDogJy9hcGkvdGltZXN0YW1wJyxcbiAgICB2YWxpZGF0ZTogZmFsc2VcbiAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwuZ2V0VGltZVN0YW1wKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKVxuICApO1xuXG4gIHJvdXRlci5wb3N0KHtcbiAgICBwYXRoOiAnL2FwaS9leHRlbnNpb25zJyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgYm9keTogc2NoZW1hLm9iamVjdCh7XG4gICAgICAgIGlkOiBzY2hlbWEuc3RyaW5nKCksXG4gICAgICAgIGV4dGVuc2lvbnM6IHNjaGVtYS5hbnkoKVxuICAgICAgfSlcbiAgICB9XG4gIH0sXG4gICAgYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiBjdHJsLnNldEV4dGVuc2lvbnMoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpXG4gICk7XG5cblxuICByb3V0ZXIuZ2V0KHtcbiAgICBwYXRoOiAnL2FwaS9leHRlbnNpb25zL3tpZH0nLFxuICAgIHZhbGlkYXRlOiB7XG4gICAgICBwYXJhbXM6IHNjaGVtYS5vYmplY3Qoe1xuICAgICAgICBpZDogc2NoZW1hLnN0cmluZygpXG4gICAgICB9KVxuICAgIH1cbiAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwuZ2V0RXh0ZW5zaW9ucyhjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICAvLyBSZXR1cm4gV2F6dWggQXBwc2V0dXAgaW5mb1xuICByb3V0ZXIuZ2V0KHtcbiAgICBwYXRoOiAnL2FwaS9zZXR1cCcsXG4gICAgdmFsaWRhdGU6IGZhbHNlLFxuICB9LFxuICAgIGFzeW5jIChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSkgPT4gY3RybC5nZXRTZXR1cEluZm8oY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpXG4gICk7XG5cbiAgLy8gUmV0dXJuIGJhc2ljIGluZm9ybWF0aW9uIG9mIHN5c2NvbGxlY3RvciBmb3IgZ2l2ZW4gYWdlbnRcbiAgcm91dGVyLmdldCh7XG4gICAgcGF0aDogJy9hcGkvc3lzY29sbGVjdG9yL3thZ2VudH0nLFxuICAgIHZhbGlkYXRlOiB7XG4gICAgICBwYXJhbXM6IHNjaGVtYS5vYmplY3Qoe1xuICAgICAgICBhZ2VudDogc2NoZW1hLnN0cmluZygpXG4gICAgICB9KVxuICAgIH1cbiAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwuZ2V0U3lzY29sbGVjdG9yKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKVxuICApO1xuXG4gIC8vIFJldHVybiBsb2dnZWQgaW4gdXNlciBoYXMgd2F6dWggZGlzYWJsZWQgYnkgcm9sZVxuICByb3V0ZXIuZ2V0KHtcbiAgICBwYXRoOiAnL2FwaS9jaGVjay13YXp1aCcsXG4gICAgdmFsaWRhdGU6IGZhbHNlXG4gIH0sXG4gICAgYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiBjdHJsLmlzV2F6dWhEaXNhYmxlZChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICAvLyBSZXR1cm4gYXBwIGxvZ29zIGNvbmZpZ3VyYXRpb25cbiAgcm91dGVyLmdldCh7XG4gICAgcGF0aDogJy9hcGkvbG9nb3MnLFxuICAgIHZhbGlkYXRlOiBmYWxzZSxcbiAgICBvcHRpb25zOiB7IGF1dGhSZXF1aXJlZDogZmFsc2UgfVxuICB9LFxuICAgIGFzeW5jIChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSkgPT4gY3RybC5nZXRBcHBMb2dvcyhjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcbn1cbiJdfQ==