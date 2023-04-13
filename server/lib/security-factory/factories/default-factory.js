"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.DefaultFactory = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _constants = require("../../../../common/constants");

var _md = _interopRequireDefault(require("md5"));

class DefaultFactory {
  constructor() {
    (0, _defineProperty2.default)(this, "platform", '');
  }

  async getCurrentUser(request, context) {
    return {
      username: _constants.ELASTIC_NAME,
      authContext: {
        username: _constants.ELASTIC_NAME
      },
      hashUsername: (0, _md.default)(_constants.ELASTIC_NAME)
    };
  }

}

exports.DefaultFactory = DefaultFactory;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImRlZmF1bHQtZmFjdG9yeS50cyJdLCJuYW1lcyI6WyJEZWZhdWx0RmFjdG9yeSIsImdldEN1cnJlbnRVc2VyIiwicmVxdWVzdCIsImNvbnRleHQiLCJ1c2VybmFtZSIsIkVMQVNUSUNfTkFNRSIsImF1dGhDb250ZXh0IiwiaGFzaFVzZXJuYW1lIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7OztBQUNBOztBQUVBOztBQUVPLE1BQU1BLGNBQU4sQ0FBZ0Q7QUFBQTtBQUFBLG9EQUNsQyxFQURrQztBQUFBOztBQUVqQyxRQUFkQyxjQUFjLENBQUNDLE9BQUQsRUFBeUJDLE9BQXpCLEVBQXlEO0FBQzNFLFdBQU87QUFDTEMsTUFBQUEsUUFBUSxFQUFFQyx1QkFETDtBQUVMQyxNQUFBQSxXQUFXLEVBQUU7QUFBRUYsUUFBQUEsUUFBUSxFQUFFQztBQUFaLE9BRlI7QUFHTEUsTUFBQUEsWUFBWSxFQUFFLGlCQUFJRix1QkFBSjtBQUhULEtBQVA7QUFLRDs7QUFSb0QiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJU2VjdXJpdHlGYWN0b3J5IH0gZnJvbSAnLi4vJztcbmltcG9ydCB7IEVMQVNUSUNfTkFNRSB9IGZyb20gJy4uLy4uLy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IHsgS2liYW5hUmVxdWVzdCwgUmVxdWVzdEhhbmRsZXJDb250ZXh0IH0gZnJvbSAnc3JjL2NvcmUvc2VydmVyJztcbmltcG9ydCBtZDUgZnJvbSAnbWQ1JztcblxuZXhwb3J0IGNsYXNzIERlZmF1bHRGYWN0b3J5IGltcGxlbWVudHMgSVNlY3VyaXR5RmFjdG9yeXtcbiAgcGxhdGZvcm06IHN0cmluZyA9ICcnO1xuICBhc3luYyBnZXRDdXJyZW50VXNlcihyZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0LCBjb250ZXh0PzpSZXF1ZXN0SGFuZGxlckNvbnRleHQpIHtcbiAgICByZXR1cm4geyBcbiAgICAgIHVzZXJuYW1lOiBFTEFTVElDX05BTUUsXG4gICAgICBhdXRoQ29udGV4dDogeyB1c2VybmFtZTogRUxBU1RJQ19OQU1FIH0sXG4gICAgICBoYXNoVXNlcm5hbWU6IG1kNShFTEFTVElDX05BTUUpXG4gICAgfTtcbiAgfVxufSJdfQ==