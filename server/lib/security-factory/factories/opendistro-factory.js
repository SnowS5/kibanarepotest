"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.OpendistroFactory = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _constants = require("../../../../common/constants");

var _md = _interopRequireDefault(require("md5"));

class OpendistroFactory {
  constructor(opendistroSecurityKibana) {
    (0, _defineProperty2.default)(this, "platform", _constants.WAZUH_SECURITY_PLUGIN_OPEN_DISTRO_FOR_ELASTICSEARCH);
    this.opendistroSecurityKibana = opendistroSecurityKibana;
  }

  async getCurrentUser(request, context) {
    try {
      const params = {
        path: `/_opendistro/_security/api/account`,
        method: 'GET'
      };
      const {
        body: authContext
      } = await context.core.elasticsearch.client.asCurrentUser.transport.request(params);
      const username = this.getUserName(authContext);
      return {
        username,
        authContext,
        hashUsername: (0, _md.default)(username)
      };
    } catch (error) {
      throw error;
    }
  }

  getUserName(authContext) {
    return authContext['user_name'];
  }

}

exports.OpendistroFactory = OpendistroFactory;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm9wZW5kaXN0cm8tZmFjdG9yeS50cyJdLCJuYW1lcyI6WyJPcGVuZGlzdHJvRmFjdG9yeSIsImNvbnN0cnVjdG9yIiwib3BlbmRpc3Ryb1NlY3VyaXR5S2liYW5hIiwiV0FaVUhfU0VDVVJJVFlfUExVR0lOX09QRU5fRElTVFJPX0ZPUl9FTEFTVElDU0VBUkNIIiwiZ2V0Q3VycmVudFVzZXIiLCJyZXF1ZXN0IiwiY29udGV4dCIsInBhcmFtcyIsInBhdGgiLCJtZXRob2QiLCJib2R5IiwiYXV0aENvbnRleHQiLCJjb3JlIiwiZWxhc3RpY3NlYXJjaCIsImNsaWVudCIsImFzQ3VycmVudFVzZXIiLCJ0cmFuc3BvcnQiLCJ1c2VybmFtZSIsImdldFVzZXJOYW1lIiwiaGFzaFVzZXJuYW1lIiwiZXJyb3IiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O0FBRUE7O0FBQ0E7O0FBRU8sTUFBTUEsaUJBQU4sQ0FBb0Q7QUFHekRDLEVBQUFBLFdBQVcsQ0FBU0Msd0JBQVQsRUFBd0M7QUFBQSxvREFGaENDLDhEQUVnQztBQUFBLFNBQS9CRCx3QkFBK0IsR0FBL0JBLHdCQUErQjtBQUNsRDs7QUFFbUIsUUFBZEUsY0FBYyxDQUFDQyxPQUFELEVBQXlCQyxPQUF6QixFQUF3RDtBQUMxRSxRQUFJO0FBQ0YsWUFBTUMsTUFBTSxHQUFHO0FBQ2JDLFFBQUFBLElBQUksRUFBRyxvQ0FETTtBQUViQyxRQUFBQSxNQUFNLEVBQUU7QUFGSyxPQUFmO0FBS0EsWUFBTTtBQUFDQyxRQUFBQSxJQUFJLEVBQUVDO0FBQVAsVUFBc0IsTUFBTUwsT0FBTyxDQUFDTSxJQUFSLENBQWFDLGFBQWIsQ0FBMkJDLE1BQTNCLENBQWtDQyxhQUFsQyxDQUFnREMsU0FBaEQsQ0FBMERYLE9BQTFELENBQWtFRSxNQUFsRSxDQUFsQztBQUNBLFlBQU1VLFFBQVEsR0FBRyxLQUFLQyxXQUFMLENBQWlCUCxXQUFqQixDQUFqQjtBQUNBLGFBQU87QUFBRU0sUUFBQUEsUUFBRjtBQUFZTixRQUFBQSxXQUFaO0FBQXlCUSxRQUFBQSxZQUFZLEVBQUUsaUJBQUlGLFFBQUo7QUFBdkMsT0FBUDtBQUNELEtBVEQsQ0FTRSxPQUFPRyxLQUFQLEVBQWM7QUFDZCxZQUFNQSxLQUFOO0FBQ0Q7QUFDRjs7QUFFREYsRUFBQUEsV0FBVyxDQUFDUCxXQUFELEVBQWtCO0FBQzNCLFdBQU9BLFdBQVcsQ0FBQyxXQUFELENBQWxCO0FBQ0Q7O0FBdkJ3RCIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IElTZWN1cml0eUZhY3RvcnkgfSBmcm9tICcuLi8nXG5pbXBvcnQgeyBLaWJhbmFSZXF1ZXN0LCBSZXF1ZXN0SGFuZGxlckNvbnRleHQgfSBmcm9tICdzcmMvY29yZS9zZXJ2ZXInO1xuaW1wb3J0IHsgV0FaVUhfU0VDVVJJVFlfUExVR0lOX09QRU5fRElTVFJPX0ZPUl9FTEFTVElDU0VBUkNIIH0gZnJvbSAnLi4vLi4vLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgbWQ1IGZyb20gJ21kNSc7XG5cbmV4cG9ydCBjbGFzcyBPcGVuZGlzdHJvRmFjdG9yeSBpbXBsZW1lbnRzIElTZWN1cml0eUZhY3Rvcnkge1xuICBwbGF0Zm9ybTogc3RyaW5nID0gV0FaVUhfU0VDVVJJVFlfUExVR0lOX09QRU5fRElTVFJPX0ZPUl9FTEFTVElDU0VBUkNIO1xuXG4gIGNvbnN0cnVjdG9yKHByaXZhdGUgb3BlbmRpc3Ryb1NlY3VyaXR5S2liYW5hOiBhbnkpIHtcbiAgfVxuXG4gIGFzeW5jIGdldEN1cnJlbnRVc2VyKHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIGNvbnRleHQ6UmVxdWVzdEhhbmRsZXJDb250ZXh0KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHBhcmFtcyA9IHtcbiAgICAgICAgcGF0aDogYC9fb3BlbmRpc3Ryby9fc2VjdXJpdHkvYXBpL2FjY291bnRgLFxuICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgfTtcblxuICAgICAgY29uc3Qge2JvZHk6IGF1dGhDb250ZXh0fSA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnRyYW5zcG9ydC5yZXF1ZXN0KHBhcmFtcyk7XG4gICAgICBjb25zdCB1c2VybmFtZSA9IHRoaXMuZ2V0VXNlck5hbWUoYXV0aENvbnRleHQpO1xuICAgICAgcmV0dXJuIHsgdXNlcm5hbWUsIGF1dGhDb250ZXh0LCBoYXNoVXNlcm5hbWU6IG1kNSh1c2VybmFtZSkgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgdGhyb3cgZXJyb3I7IFxuICAgIH1cbiAgfVxuXG4gIGdldFVzZXJOYW1lKGF1dGhDb250ZXh0OmFueSkge1xuICAgIHJldHVybiBhdXRoQ29udGV4dFsndXNlcl9uYW1lJ11cbiAgfVxufSJdfQ==