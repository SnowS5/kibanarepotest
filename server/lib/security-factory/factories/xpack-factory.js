"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.XpackFactory = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _constants = require("../../../../common/constants");

var _md = _interopRequireDefault(require("md5"));

class XpackFactory {
  constructor(security) {
    (0, _defineProperty2.default)(this, "platform", _constants.WAZUH_SECURITY_PLUGIN_XPACK_SECURITY);
    this.security = security;
  }

  async getCurrentUser(request) {
    try {
      const authContext = await this.security.authc.getCurrentUser(request);
      if (!authContext) return {
        hashUsername: (0, _md.default)(_constants.ELASTIC_NAME),
        username: _constants.ELASTIC_NAME,
        authContext: {
          username: _constants.ELASTIC_NAME
        }
      };
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
    return authContext['username'];
  }

}

exports.XpackFactory = XpackFactory;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInhwYWNrLWZhY3RvcnkudHMiXSwibmFtZXMiOlsiWHBhY2tGYWN0b3J5IiwiY29uc3RydWN0b3IiLCJzZWN1cml0eSIsIldBWlVIX1NFQ1VSSVRZX1BMVUdJTl9YUEFDS19TRUNVUklUWSIsImdldEN1cnJlbnRVc2VyIiwicmVxdWVzdCIsImF1dGhDb250ZXh0IiwiYXV0aGMiLCJoYXNoVXNlcm5hbWUiLCJFTEFTVElDX05BTUUiLCJ1c2VybmFtZSIsImdldFVzZXJOYW1lIiwiZXJyb3IiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O0FBR0E7O0FBQ0E7O0FBRU8sTUFBTUEsWUFBTixDQUErQztBQUVwREMsRUFBQUEsV0FBVyxDQUFTQyxRQUFULEVBQXdDO0FBQUEsb0RBRGhDQywrQ0FDZ0M7QUFBQSxTQUEvQkQsUUFBK0IsR0FBL0JBLFFBQStCO0FBQUU7O0FBRWpDLFFBQWRFLGNBQWMsQ0FBQ0MsT0FBRCxFQUF5QjtBQUMzQyxRQUFJO0FBQ0YsWUFBTUMsV0FBVyxHQUFHLE1BQU0sS0FBS0osUUFBTCxDQUFjSyxLQUFkLENBQW9CSCxjQUFwQixDQUFtQ0MsT0FBbkMsQ0FBMUI7QUFDQSxVQUFHLENBQUNDLFdBQUosRUFBaUIsT0FBTztBQUFDRSxRQUFBQSxZQUFZLEVBQUUsaUJBQUlDLHVCQUFKLENBQWY7QUFBa0NDLFFBQUFBLFFBQVEsRUFBRUQsdUJBQTVDO0FBQTBESCxRQUFBQSxXQUFXLEVBQUU7QUFBRUksVUFBQUEsUUFBUSxFQUFFRDtBQUFaO0FBQXZFLE9BQVA7QUFDakIsWUFBTUMsUUFBUSxHQUFHLEtBQUtDLFdBQUwsQ0FBaUJMLFdBQWpCLENBQWpCO0FBQ0EsYUFBTztBQUFFSSxRQUFBQSxRQUFGO0FBQVlKLFFBQUFBLFdBQVo7QUFBeUJFLFFBQUFBLFlBQVksRUFBRSxpQkFBSUUsUUFBSjtBQUF2QyxPQUFQO0FBQ0QsS0FMRCxDQUtFLE9BQU9FLEtBQVAsRUFBYztBQUNkLFlBQU1BLEtBQU47QUFDRDtBQUNGOztBQUVERCxFQUFBQSxXQUFXLENBQUNMLFdBQUQsRUFBa0I7QUFDM0IsV0FBT0EsV0FBVyxDQUFDLFVBQUQsQ0FBbEI7QUFDRDs7QUFqQm1EIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSVNlY3VyaXR5RmFjdG9yeSB9IGZyb20gJy4uLydcbmltcG9ydCB7IFNlY3VyaXR5UGx1Z2luU2V0dXAgfSBmcm9tICd4LXBhY2svcGx1Z2lucy9zZWN1cml0eS9zZXJ2ZXInO1xuaW1wb3J0IHsgS2liYW5hUmVxdWVzdCB9IGZyb20gJ3NyYy9jb3JlL3NlcnZlcic7XG5pbXBvcnQgeyBXQVpVSF9TRUNVUklUWV9QTFVHSU5fWFBBQ0tfU0VDVVJJVFksIEVMQVNUSUNfTkFNRSB9IGZyb20gJy4uLy4uLy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IG1kNSBmcm9tICdtZDUnO1xuXG5leHBvcnQgY2xhc3MgWHBhY2tGYWN0b3J5IGltcGxlbWVudHMgSVNlY3VyaXR5RmFjdG9yeSB7XG4gIHBsYXRmb3JtOiBzdHJpbmcgPSBXQVpVSF9TRUNVUklUWV9QTFVHSU5fWFBBQ0tfU0VDVVJJVFk7XG4gIGNvbnN0cnVjdG9yKHByaXZhdGUgc2VjdXJpdHk6IFNlY3VyaXR5UGx1Z2luU2V0dXApIHt9XG5cbiAgYXN5bmMgZ2V0Q3VycmVudFVzZXIocmVxdWVzdDogS2liYW5hUmVxdWVzdCkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBhdXRoQ29udGV4dCA9IGF3YWl0IHRoaXMuc2VjdXJpdHkuYXV0aGMuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCk7XG4gICAgICBpZighYXV0aENvbnRleHQpIHJldHVybiB7aGFzaFVzZXJuYW1lOiBtZDUoRUxBU1RJQ19OQU1FKSwgdXNlcm5hbWU6IEVMQVNUSUNfTkFNRSwgYXV0aENvbnRleHQ6IHsgdXNlcm5hbWU6IEVMQVNUSUNfTkFNRX19O1xuICAgICAgY29uc3QgdXNlcm5hbWUgPSB0aGlzLmdldFVzZXJOYW1lKGF1dGhDb250ZXh0KTtcbiAgICAgIHJldHVybiB7IHVzZXJuYW1lLCBhdXRoQ29udGV4dCwgaGFzaFVzZXJuYW1lOiBtZDUodXNlcm5hbWUpIH07XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHRocm93IGVycm9yOyBcbiAgICB9XG4gIH1cblxuICBnZXRVc2VyTmFtZShhdXRoQ29udGV4dDphbnkpIHtcbiAgICByZXR1cm4gYXV0aENvbnRleHRbJ3VzZXJuYW1lJ107XG4gIH1cbn0iXX0=