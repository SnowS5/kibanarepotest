"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.addJobToQueue = addJobToQueue;
exports.jobQueueRun = jobQueueRun;
exports.queue = void 0;

var _nodeCron = _interopRequireDefault(require("node-cron"));

var _logger = require("../../lib/logger");

var _constants = require("../../../common/constants");

/*
 * Wazuh app - Add delayed jobs to a queue.
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
let queue = [];
exports.queue = queue;
;
/**
 * Add a job to the queue.
 * @param job Job to add to queue
 */

function addJobToQueue(job) {
  (0, _logger.log)('queue:addJob', `New job added`, 'debug');
  queue.push(job);
}

;

async function executePendingJobs() {
  try {
    if (!queue || !queue.length) return;
    const now = new Date();
    const pendingJobs = queue.filter(item => item.startAt <= now);
    (0, _logger.log)('queue:executePendingJobs', `Pending jobs: ${pendingJobs.length}`, 'debug');

    if (!pendingJobs || !pendingJobs.length) {
      return;
    }

    ;
    exports.queue = queue = queue.filter(item => item.startAt > now);

    for (const job of pendingJobs) {
      try {
        await job.run();
      } catch (error) {
        continue;
      }

      ;
    }
  } catch (error) {
    exports.queue = queue = [];
    (0, _logger.log)('queue:executePendingJobs', error.message || error);
    return Promise.reject(error);
  }
}
/**
 * Run the job queue it plugin start.
 * @param context 
 */


function jobQueueRun(context) {
  _nodeCron.default.schedule(_constants.WAZUH_QUEUE_CRON_FREQ, async () => {
    try {
      await executePendingJobs();
    } catch (error) {
      (0, _logger.log)('queue:launchCronJob', error.message || error);
    }
  });
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluZGV4LnRzIl0sIm5hbWVzIjpbInF1ZXVlIiwiYWRkSm9iVG9RdWV1ZSIsImpvYiIsInB1c2giLCJleGVjdXRlUGVuZGluZ0pvYnMiLCJsZW5ndGgiLCJub3ciLCJEYXRlIiwicGVuZGluZ0pvYnMiLCJmaWx0ZXIiLCJpdGVtIiwic3RhcnRBdCIsInJ1biIsImVycm9yIiwibWVzc2FnZSIsIlByb21pc2UiLCJyZWplY3QiLCJqb2JRdWV1ZVJ1biIsImNvbnRleHQiLCJjcm9uIiwic2NoZWR1bGUiLCJXQVpVSF9RVUVVRV9DUk9OX0ZSRVEiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O0FBV0E7O0FBQ0E7O0FBQ0E7O0FBYkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUtPLElBQUlBLEtBQUssR0FBRyxFQUFaOztBQU9OO0FBRUQ7QUFDQTtBQUNBO0FBQ0E7O0FBQ08sU0FBU0MsYUFBVCxDQUF1QkMsR0FBdkIsRUFBdUM7QUFDNUMsbUJBQUksY0FBSixFQUFxQixlQUFyQixFQUFxQyxPQUFyQztBQUNBRixFQUFBQSxLQUFLLENBQUNHLElBQU4sQ0FBV0QsR0FBWDtBQUNEOztBQUFBOztBQUVELGVBQWVFLGtCQUFmLEdBQW9DO0FBQ2xDLE1BQUk7QUFDRixRQUFJLENBQUNKLEtBQUQsSUFBVSxDQUFDQSxLQUFLLENBQUNLLE1BQXJCLEVBQTZCO0FBQzdCLFVBQU1DLEdBQVMsR0FBRyxJQUFJQyxJQUFKLEVBQWxCO0FBQ0EsVUFBTUMsV0FBd0IsR0FBR1IsS0FBSyxDQUFDUyxNQUFOLENBQWFDLElBQUksSUFBSUEsSUFBSSxDQUFDQyxPQUFMLElBQWdCTCxHQUFyQyxDQUFqQztBQUNBLHFCQUNFLDBCQURGLEVBRUcsaUJBQWdCRSxXQUFXLENBQUNILE1BQU8sRUFGdEMsRUFHRSxPQUhGOztBQUtBLFFBQUksQ0FBQ0csV0FBRCxJQUFnQixDQUFDQSxXQUFXLENBQUNILE1BQWpDLEVBQXdDO0FBQ3RDO0FBQ0Q7O0FBQUE7QUFDRCxvQkFBQUwsS0FBSyxHQUFHQSxLQUFLLENBQUNTLE1BQU4sQ0FBY0MsSUFBRCxJQUFxQkEsSUFBSSxDQUFDQyxPQUFMLEdBQWVMLEdBQWpELENBQVI7O0FBRUEsU0FBSyxNQUFNSixHQUFYLElBQWtCTSxXQUFsQixFQUErQjtBQUM3QixVQUFJO0FBQ0YsY0FBTU4sR0FBRyxDQUFDVSxHQUFKLEVBQU47QUFDRCxPQUZELENBRUUsT0FBT0MsS0FBUCxFQUFjO0FBQ2Q7QUFDRDs7QUFBQTtBQUNGO0FBQ0YsR0FyQkQsQ0FxQkUsT0FBT0EsS0FBUCxFQUFjO0FBQ2Qsb0JBQUFiLEtBQUssR0FBRyxFQUFSO0FBQ0EscUJBQUksMEJBQUosRUFBZ0NhLEtBQUssQ0FBQ0MsT0FBTixJQUFpQkQsS0FBakQ7QUFDQSxXQUFPRSxPQUFPLENBQUNDLE1BQVIsQ0FBZUgsS0FBZixDQUFQO0FBQ0Q7QUFDRjtBQUVEO0FBQ0E7QUFDQTtBQUNBOzs7QUFDTyxTQUFTSSxXQUFULENBQXFCQyxPQUFyQixFQUE4QjtBQUNuQ0Msb0JBQUtDLFFBQUwsQ0FDRUMsZ0NBREYsRUFFRSxZQUFZO0FBQ1YsUUFBSTtBQUNGLFlBQU1qQixrQkFBa0IsRUFBeEI7QUFDRCxLQUZELENBRUUsT0FBT1MsS0FBUCxFQUFjO0FBQ2QsdUJBQUkscUJBQUosRUFBMkJBLEtBQUssQ0FBQ0MsT0FBTixJQUFpQkQsS0FBNUM7QUFDRDtBQUNGLEdBUkg7QUFVRCIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBBZGQgZGVsYXllZCBqb2JzIHRvIGEgcXVldWUuXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IGNyb24gZnJvbSAnbm9kZS1jcm9uJztcbmltcG9ydCB7IGxvZyB9IGZyb20gJy4uLy4uL2xpYi9sb2dnZXInO1xuaW1wb3J0IHsgV0FaVUhfUVVFVUVfQ1JPTl9GUkVRIH0gZnJvbSAnLi4vLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5cbmV4cG9ydCBsZXQgcXVldWUgPSBbXTtcblxuZXhwb3J0IGludGVyZmFjZSBJUXVldWVKb2J7XG4gIC8qKiBEYXRlIG9iamVjdCB0byBzdGFydCB0aGUgam9iICovXG4gIHN0YXJ0QXQ6IERhdGVcbiAgLyoqIEZ1bmN0aW9uIHRvIGV4ZWN1dGUgKi9cbiAgcnVuOiAoKSA9PiB2b2lkXG59O1xuXG4vKipcbiAqIEFkZCBhIGpvYiB0byB0aGUgcXVldWUuXG4gKiBAcGFyYW0gam9iIEpvYiB0byBhZGQgdG8gcXVldWVcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFkZEpvYlRvUXVldWUoam9iOiBJUXVldWVKb2IpIHtcbiAgbG9nKCdxdWV1ZTphZGRKb2InLCBgTmV3IGpvYiBhZGRlZGAsICdkZWJ1ZycpO1xuICBxdWV1ZS5wdXNoKGpvYik7XG59O1xuXG5hc3luYyBmdW5jdGlvbiBleGVjdXRlUGVuZGluZ0pvYnMoKSB7XG4gIHRyeSB7XG4gICAgaWYgKCFxdWV1ZSB8fCAhcXVldWUubGVuZ3RoKSByZXR1cm47XG4gICAgY29uc3Qgbm93OiBEYXRlID0gbmV3IERhdGUoKTtcbiAgICBjb25zdCBwZW5kaW5nSm9iczogSVF1ZXVlSm9iW10gPSBxdWV1ZS5maWx0ZXIoaXRlbSA9PiBpdGVtLnN0YXJ0QXQgPD0gbm93KTtcbiAgICBsb2coXG4gICAgICAncXVldWU6ZXhlY3V0ZVBlbmRpbmdKb2JzJyxcbiAgICAgIGBQZW5kaW5nIGpvYnM6ICR7cGVuZGluZ0pvYnMubGVuZ3RofWAsXG4gICAgICAnZGVidWcnXG4gICAgKTtcbiAgICBpZiAoIXBlbmRpbmdKb2JzIHx8ICFwZW5kaW5nSm9icy5sZW5ndGgpe1xuICAgICAgcmV0dXJuO1xuICAgIH07XG4gICAgcXVldWUgPSBxdWV1ZS5maWx0ZXIoKGl0ZW06IElRdWV1ZUpvYikgPT4gaXRlbS5zdGFydEF0ID4gbm93KTtcblxuICAgIGZvciAoY29uc3Qgam9iIG9mIHBlbmRpbmdKb2JzKSB7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCBqb2IucnVuKCk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH07XG4gICAgfVxuICB9IGNhdGNoIChlcnJvcikge1xuICAgIHF1ZXVlID0gW107XG4gICAgbG9nKCdxdWV1ZTpleGVjdXRlUGVuZGluZ0pvYnMnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICB9XG59XG5cbi8qKlxuICogUnVuIHRoZSBqb2IgcXVldWUgaXQgcGx1Z2luIHN0YXJ0LlxuICogQHBhcmFtIGNvbnRleHQgXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBqb2JRdWV1ZVJ1bihjb250ZXh0KSB7XG4gIGNyb24uc2NoZWR1bGUoXG4gICAgV0FaVUhfUVVFVUVfQ1JPTl9GUkVRLFxuICAgIGFzeW5jICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IGV4ZWN1dGVQZW5kaW5nSm9icygpO1xuICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgbG9nKCdxdWV1ZTpsYXVuY2hDcm9uSm9iJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICB9XG4gICAgfVxuICApO1xufVxuIl19