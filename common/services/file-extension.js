"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getFileExtensionFromBuffer = getFileExtensionFromBuffer;

/**
 * Get the file extension from a file buffer. Calculates the image format by reading the first 4 bytes of the image (header)
 * Supported types: jpeg, jpg, png, svg
 * Additionally, this function allows checking gif images.
 * @param buffer file buffer
 * @returns the file extension. Example: jpg, png, svg. it Returns unknown if it can not find the extension.
*/
function getFileExtensionFromBuffer(buffer) {
  const imageFormat = buffer.toString('hex').substring(0, 4);

  switch (imageFormat) {
    case '4749':
      return 'gif';

    case 'ffd8':
      return 'jpg';
    // Also jpeg

    case '8950':
      return 'png';

    case '3c73':
    case '3c3f':
      return 'svg';

    default:
      return 'unknown';
  }
}

;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImZpbGUtZXh0ZW5zaW9uLnRzIl0sIm5hbWVzIjpbImdldEZpbGVFeHRlbnNpb25Gcm9tQnVmZmVyIiwiYnVmZmVyIiwiaW1hZ2VGb3JtYXQiLCJ0b1N0cmluZyIsInN1YnN0cmluZyJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ08sU0FBU0EsMEJBQVQsQ0FBb0NDLE1BQXBDLEVBQTREO0FBQ2xFLFFBQU1DLFdBQVcsR0FBR0QsTUFBTSxDQUFDRSxRQUFQLENBQWdCLEtBQWhCLEVBQXVCQyxTQUF2QixDQUFpQyxDQUFqQyxFQUFvQyxDQUFwQyxDQUFwQjs7QUFDQSxVQUFRRixXQUFSO0FBQ0MsU0FBSyxNQUFMO0FBQ0MsYUFBTyxLQUFQOztBQUNELFNBQUssTUFBTDtBQUNDLGFBQU8sS0FBUDtBQUFjOztBQUNmLFNBQUssTUFBTDtBQUNDLGFBQU8sS0FBUDs7QUFDQyxTQUFLLE1BQUw7QUFDQSxTQUFLLE1BQUw7QUFDRCxhQUFPLEtBQVA7O0FBQ0Q7QUFDQyxhQUFPLFNBQVA7QUFYRjtBQWFBOztBQUFBIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBHZXQgdGhlIGZpbGUgZXh0ZW5zaW9uIGZyb20gYSBmaWxlIGJ1ZmZlci4gQ2FsY3VsYXRlcyB0aGUgaW1hZ2UgZm9ybWF0IGJ5IHJlYWRpbmcgdGhlIGZpcnN0IDQgYnl0ZXMgb2YgdGhlIGltYWdlIChoZWFkZXIpXG4gKiBTdXBwb3J0ZWQgdHlwZXM6IGpwZWcsIGpwZywgcG5nLCBzdmdcbiAqIEFkZGl0aW9uYWxseSwgdGhpcyBmdW5jdGlvbiBhbGxvd3MgY2hlY2tpbmcgZ2lmIGltYWdlcy5cbiAqIEBwYXJhbSBidWZmZXIgZmlsZSBidWZmZXJcbiAqIEByZXR1cm5zIHRoZSBmaWxlIGV4dGVuc2lvbi4gRXhhbXBsZToganBnLCBwbmcsIHN2Zy4gaXQgUmV0dXJucyB1bmtub3duIGlmIGl0IGNhbiBub3QgZmluZCB0aGUgZXh0ZW5zaW9uLlxuKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRGaWxlRXh0ZW5zaW9uRnJvbUJ1ZmZlcihidWZmZXI6IEJ1ZmZlcik6IHN0cmluZyB7XG5cdGNvbnN0IGltYWdlRm9ybWF0ID0gYnVmZmVyLnRvU3RyaW5nKCdoZXgnKS5zdWJzdHJpbmcoMCwgNCk7XG5cdHN3aXRjaCAoaW1hZ2VGb3JtYXQpIHtcblx0XHRjYXNlICc0NzQ5Jzpcblx0XHRcdHJldHVybiAnZ2lmJztcblx0XHRjYXNlICdmZmQ4Jzpcblx0XHRcdHJldHVybiAnanBnJzsgLy8gQWxzbyBqcGVnXG5cdFx0Y2FzZSAnODk1MCc6XG5cdFx0XHRyZXR1cm4gJ3BuZyc7XG4gICAgY2FzZSAnM2M3Myc6XG4gICAgY2FzZSAnM2MzZic6XG5cdFx0XHRyZXR1cm4gJ3N2Zyc7XG5cdFx0ZGVmYXVsdDpcblx0XHRcdHJldHVybiAndW5rbm93bic7XG5cdH1cbn07XG4iXX0=