"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ApiRequest = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var ApiInterceptor = _interopRequireWildcard(require("../../lib/api-interceptor.js"));

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

class ApiRequest {
  constructor(request, api, params = {}) {
    (0, _defineProperty2.default)(this, "api", void 0);
    (0, _defineProperty2.default)(this, "request", void 0);
    (0, _defineProperty2.default)(this, "params", void 0);
    this.request = request;
    this.api = api;
    this.params = params;
  }

  async makeRequest() {
    const {
      id,
      url,
      port
    } = this.api;
    const response = await ApiInterceptor.requestAsInternalUser('GET', '/${this.request}', this.params, {
      apiHostID: id
    });
    return response;
  }

  async getData() {
    try {
      const response = await this.makeRequest();
      if (response.status !== 200) throw response;
      return response.data;
    } catch (error) {
      if (error.status === 404) {
        throw {
          error: 404,
          message: error.data.detail
        };
      }

      if (error.response && error.response.status === 401) {
        throw {
          error: 401,
          message: 'Wrong Wazuh API credentials used'
        };
      }

      if (error && error.data && error.data.detail && error.data.detail === 'ECONNRESET') {
        throw {
          error: 3005,
          message: 'Wrong protocol being used to connect to the Wazuh API'
        };
      }

      if (error && error.data && error.data.detail && ['ENOTFOUND', 'EHOSTUNREACH', 'EINVAL', 'EAI_AGAIN', 'ECONNREFUSED'].includes(error.data.detail)) {
        throw {
          error: 3005,
          message: 'Wazuh API is not reachable. Please check your url and port.'
        };
      }

      throw error;
    }
  }

}

exports.ApiRequest = ApiRequest;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwaVJlcXVlc3QudHMiXSwibmFtZXMiOlsiQXBpUmVxdWVzdCIsImNvbnN0cnVjdG9yIiwicmVxdWVzdCIsImFwaSIsInBhcmFtcyIsIm1ha2VSZXF1ZXN0IiwiaWQiLCJ1cmwiLCJwb3J0IiwicmVzcG9uc2UiLCJBcGlJbnRlcmNlcHRvciIsInJlcXVlc3RBc0ludGVybmFsVXNlciIsImFwaUhvc3RJRCIsImdldERhdGEiLCJzdGF0dXMiLCJkYXRhIiwiZXJyb3IiLCJtZXNzYWdlIiwiZGV0YWlsIiwiaW5jbHVkZXMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O0FBQ0E7Ozs7OztBQWVPLE1BQU1BLFVBQU4sQ0FBaUI7QUFLdEJDLEVBQUFBLFdBQVcsQ0FBQ0MsT0FBRCxFQUFpQkMsR0FBakIsRUFBMkJDLE1BQVMsR0FBQyxFQUFyQyxFQUEyQztBQUFBO0FBQUE7QUFBQTtBQUNwRCxTQUFLRixPQUFMLEdBQWVBLE9BQWY7QUFDQSxTQUFLQyxHQUFMLEdBQVdBLEdBQVg7QUFDQSxTQUFLQyxNQUFMLEdBQWNBLE1BQWQ7QUFDRDs7QUFFd0IsUUFBWEMsV0FBVyxHQUEwQjtBQUNqRCxVQUFNO0FBQUNDLE1BQUFBLEVBQUQ7QUFBS0MsTUFBQUEsR0FBTDtBQUFVQyxNQUFBQTtBQUFWLFFBQWtCLEtBQUtMLEdBQTdCO0FBRUEsVUFBTU0sUUFBdUIsR0FBRyxNQUFNQyxjQUFjLENBQUNDLHFCQUFmLENBQ3BDLEtBRG9DLEVBRXBDLGtCQUZvQyxFQUdwQyxLQUFLUCxNQUgrQixFQUlwQztBQUFDUSxNQUFBQSxTQUFTLEVBQUVOO0FBQVosS0FKb0MsQ0FBdEM7QUFNQSxXQUFPRyxRQUFQO0FBQ0Q7O0FBRW1CLFFBQVBJLE9BQU8sR0FBbUI7QUFDckMsUUFBSTtBQUNGLFlBQU1KLFFBQVEsR0FBRyxNQUFNLEtBQUtKLFdBQUwsRUFBdkI7QUFDQSxVQUFJSSxRQUFRLENBQUNLLE1BQVQsS0FBb0IsR0FBeEIsRUFBNkIsTUFBTUwsUUFBTjtBQUM3QixhQUFPQSxRQUFRLENBQUNNLElBQWhCO0FBQ0QsS0FKRCxDQUlFLE9BQU9DLEtBQVAsRUFBYztBQUNkLFVBQUlBLEtBQUssQ0FBQ0YsTUFBTixLQUFpQixHQUFyQixFQUEwQjtBQUN4QixjQUFNO0FBQUNFLFVBQUFBLEtBQUssRUFBRSxHQUFSO0FBQWFDLFVBQUFBLE9BQU8sRUFBRUQsS0FBSyxDQUFDRCxJQUFOLENBQVdHO0FBQWpDLFNBQU47QUFDRDs7QUFDRCxVQUFJRixLQUFLLENBQUNQLFFBQU4sSUFBa0JPLEtBQUssQ0FBQ1AsUUFBTixDQUFlSyxNQUFmLEtBQTBCLEdBQWhELEVBQW9EO0FBQ2xELGNBQU07QUFBQ0UsVUFBQUEsS0FBSyxFQUFFLEdBQVI7QUFBYUMsVUFBQUEsT0FBTyxFQUFFO0FBQXRCLFNBQU47QUFDRDs7QUFDRCxVQUFJRCxLQUFLLElBQUlBLEtBQUssQ0FBQ0QsSUFBZixJQUF1QkMsS0FBSyxDQUFDRCxJQUFOLENBQVdHLE1BQWxDLElBQTRDRixLQUFLLENBQUNELElBQU4sQ0FBV0csTUFBWCxLQUFzQixZQUF0RSxFQUFvRjtBQUNsRixjQUFNO0FBQUNGLFVBQUFBLEtBQUssRUFBRSxJQUFSO0FBQWNDLFVBQUFBLE9BQU8sRUFBRTtBQUF2QixTQUFOO0FBQ0Q7O0FBQ0QsVUFBSUQsS0FBSyxJQUFJQSxLQUFLLENBQUNELElBQWYsSUFBdUJDLEtBQUssQ0FBQ0QsSUFBTixDQUFXRyxNQUFsQyxJQUE0QyxDQUFDLFdBQUQsRUFBYSxjQUFiLEVBQTRCLFFBQTVCLEVBQXFDLFdBQXJDLEVBQWlELGNBQWpELEVBQWlFQyxRQUFqRSxDQUEwRUgsS0FBSyxDQUFDRCxJQUFOLENBQVdHLE1BQXJGLENBQWhELEVBQThJO0FBQzVJLGNBQU07QUFBQ0YsVUFBQUEsS0FBSyxFQUFFLElBQVI7QUFBY0MsVUFBQUEsT0FBTyxFQUFFO0FBQXZCLFNBQU47QUFDRDs7QUFDRCxZQUFNRCxLQUFOO0FBQ0Q7QUFDRjs7QUEzQ3FCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQXhpb3NSZXNwb25zZSB9ZnJvbSAnYXhpb3MnO1xuaW1wb3J0ICogYXMgQXBpSW50ZXJjZXB0b3IgIGZyb20gJy4uLy4uL2xpYi9hcGktaW50ZXJjZXB0b3IuanMnO1xuXG5leHBvcnQgaW50ZXJmYWNlIElBcGkge1xuICBpZDogc3RyaW5nXG4gIHVzZXI6IHN0cmluZ1xuICBwYXNzd29yZDogc3RyaW5nXG4gIHVybDogc3RyaW5nXG4gIHBvcnQ6IG51bWJlclxuICBjbHVzdGVyX2luZm86IHtcbiAgICBtYW5hZ2VyOiBzdHJpbmdcbiAgICBjbHVzdGVyOiAnRGlzYWJsZWQnIHwgJ0VuYWJsZWQnXG4gICAgc3RhdHVzOiAnZGlzYWJsZWQnIHwgJ2VuYWJsZWQnXG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIEFwaVJlcXVlc3Qge1xuICBwcml2YXRlIGFwaTogSUFwaTtcbiAgcHJpdmF0ZSByZXF1ZXN0OiBzdHJpbmc7XG4gIHByaXZhdGUgcGFyYW1zOiB7fTtcblxuICBjb25zdHJ1Y3RvcihyZXF1ZXN0OnN0cmluZywgYXBpOklBcGksIHBhcmFtczp7fT17fSwgKSB7XG4gICAgdGhpcy5yZXF1ZXN0ID0gcmVxdWVzdDtcbiAgICB0aGlzLmFwaSA9IGFwaTtcbiAgICB0aGlzLnBhcmFtcyA9IHBhcmFtcztcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgbWFrZVJlcXVlc3QoKTpQcm9taXNlPEF4aW9zUmVzcG9uc2U+IHtcbiAgICBjb25zdCB7aWQsIHVybCwgcG9ydH0gPSB0aGlzLmFwaTtcbiAgICBcbiAgICBjb25zdCByZXNwb25zZTogQXhpb3NSZXNwb25zZSA9IGF3YWl0IEFwaUludGVyY2VwdG9yLnJlcXVlc3RBc0ludGVybmFsVXNlcihcbiAgICAgICdHRVQnLFxuICAgICAgJy8ke3RoaXMucmVxdWVzdH0nLFxuICAgICAgdGhpcy5wYXJhbXMsXG4gICAgICB7YXBpSG9zdElEOiBpZCB9XG4gICAgKVxuICAgIHJldHVybiByZXNwb25zZTtcbiAgfVxuXG4gIHB1YmxpYyBhc3luYyBnZXREYXRhKCk6UHJvbWlzZTxvYmplY3Q+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCB0aGlzLm1ha2VSZXF1ZXN0KCk7XG4gICAgICBpZiAocmVzcG9uc2Uuc3RhdHVzICE9PSAyMDApIHRocm93IHJlc3BvbnNlO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGlmIChlcnJvci5zdGF0dXMgPT09IDQwNCkge1xuICAgICAgICB0aHJvdyB7ZXJyb3I6IDQwNCwgbWVzc2FnZTogZXJyb3IuZGF0YS5kZXRhaWx9O1xuICAgICAgfVxuICAgICAgaWYgKGVycm9yLnJlc3BvbnNlICYmIGVycm9yLnJlc3BvbnNlLnN0YXR1cyA9PT0gNDAxKXtcbiAgICAgICAgdGhyb3cge2Vycm9yOiA0MDEsIG1lc3NhZ2U6ICdXcm9uZyBXYXp1aCBBUEkgY3JlZGVudGlhbHMgdXNlZCd9O1xuICAgICAgfVxuICAgICAgaWYgKGVycm9yICYmIGVycm9yLmRhdGEgJiYgZXJyb3IuZGF0YS5kZXRhaWwgJiYgZXJyb3IuZGF0YS5kZXRhaWwgPT09ICdFQ09OTlJFU0VUJykge1xuICAgICAgICB0aHJvdyB7ZXJyb3I6IDMwMDUsIG1lc3NhZ2U6ICdXcm9uZyBwcm90b2NvbCBiZWluZyB1c2VkIHRvIGNvbm5lY3QgdG8gdGhlIFdhenVoIEFQSSd9O1xuICAgICAgfVxuICAgICAgaWYgKGVycm9yICYmIGVycm9yLmRhdGEgJiYgZXJyb3IuZGF0YS5kZXRhaWwgJiYgWydFTk9URk9VTkQnLCdFSE9TVFVOUkVBQ0gnLCdFSU5WQUwnLCdFQUlfQUdBSU4nLCdFQ09OTlJFRlVTRUQnXS5pbmNsdWRlcyhlcnJvci5kYXRhLmRldGFpbCkpIHtcbiAgICAgICAgdGhyb3cge2Vycm9yOiAzMDA1LCBtZXNzYWdlOiAnV2F6dWggQVBJIGlzIG5vdCByZWFjaGFibGUuIFBsZWFzZSBjaGVjayB5b3VyIHVybCBhbmQgcG9ydC4nfTtcbiAgICAgIH1cbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxufSJdfQ==