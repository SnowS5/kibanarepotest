"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.SettingsValidator = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _path = _interopRequireDefault(require("path"));

var _fileSize = require("./file-size");

class SettingsValidator {
  /**
   * Create a function that is a composition of the input validations
   * @param functions SettingsValidator functions to compose
   * @returns composed validation
   */
  static compose(...functions) {
    return function composedValidation(value) {
      for (const fn of functions) {
        const result = fn(value);

        if (typeof result === 'string' && result.length > 0) {
          return result;
        }

        ;
      }

      ;
    };
  }

  /**
   * Check the value is a string
   * @param value
   * @returns
   */
  static isString(value) {
    return typeof value === 'string' ? undefined : "Value is not a string.";
  }

  /**
   * Check the string has no spaces
   * @param value
   * @returns
   */
  static hasNoSpaces(value) {
    return /^\S*$/.test(value) ? undefined : "No whitespaces allowed.";
  }

  /**
   * Check the string has no empty
   * @param value
   * @returns
   */
  static isNotEmptyString(value) {
    if (typeof value === 'string') {
      if (value.length === 0) {
        return "Value can not be empty.";
      } else {
        return undefined;
      }
    }

    ;
  }

  /**
   * Check the number of string lines is limited
   * @param options
   * @returns
   */
  static multipleLinesString(options = {}) {
    return function (value) {
      const lines = value.split(/\r\n|\r|\n/).length;

      if (typeof options.maxLength !== 'undefined' && value.split('\n').some(line => line.length > options.maxLength)) {
        return `The maximum length of a line is ${options.maxLength} characters.`;
      }

      ;

      if (typeof options.minRows !== 'undefined' && lines < options.minRows) {
        return `The string should have more or ${options.minRows} line/s.`;
      }

      ;

      if (typeof options.maxRows !== 'undefined' && lines > options.maxRows) {
        return `The string should have less or equal to ${options.maxRows} line/s.`;
      }

      ;
    };
  }

  /**
   * Creates a function that checks the string does not contain some characters
   * @param invalidCharacters
   * @returns
   */
  static hasNotInvalidCharacters(...invalidCharacters) {
    return function (value) {
      return invalidCharacters.some(invalidCharacter => value.includes(invalidCharacter)) ? `It can't contain invalid characters: ${invalidCharacters.join(', ')}.` : undefined;
    };
  }

  /**
   * Creates a function that checks the string does not start with a substring
   * @param invalidStartingCharacters
   * @returns
   */
  static noStartsWithString(...invalidStartingCharacters) {
    return function (value) {
      return invalidStartingCharacters.some(invalidStartingCharacter => value.startsWith(invalidStartingCharacter)) ? `It can't start with: ${invalidStartingCharacters.join(', ')}.` : undefined;
    };
  }

  /**
   * Creates a function that checks the string is not equals to some values
   * @param invalidLiterals
   * @returns
   */
  static noLiteralString(...invalidLiterals) {
    return function (value) {
      return invalidLiterals.some(invalidLiteral => value === invalidLiteral) ? `It can't be: ${invalidLiterals.join(', ')}.` : undefined;
    };
  }

  /**
   * Check the value is a boolean
   * @param value
   * @returns
   */
  static isBoolean(value) {
    return typeof value === 'boolean' ? undefined : "It should be a boolean. Allowed values: true or false.";
  }

  /**
   * Check the value is a number between some optional limits
   * @param options
   * @returns
   */
  static number(options = {}) {
    return function (value) {
      if (options.integer && ((typeof value === 'string' ? ['.', ','].some(character => value.includes(character)) : false) || !Number.isInteger(Number(value)))) {
        return 'Number should be an integer.';
      }

      ;
      const valueNumber = typeof value === 'string' ? Number(value) : value;

      if (typeof options.min !== 'undefined' && valueNumber < options.min) {
        return `Value should be greater or equal than ${options.min}.`;
      }

      ;

      if (typeof options.max !== 'undefined' && valueNumber > options.max) {
        return `Value should be lower or equal than ${options.max}.`;
      }

      ;
    };
  }

  /**
   * Creates a function that checks if the value is a json
   * @param validateParsed Optional parameter to validate the parsed object
   * @returns
   */
  static json(validateParsed) {
    return function (value) {
      let jsonObject; // Try to parse the string as JSON

      try {
        jsonObject = JSON.parse(value);
      } catch (error) {
        return "Value can't be parsed. There is some error.";
      }

      ;
      return validateParsed ? validateParsed(jsonObject) : undefined;
    };
  }

  /**
   * Creates a function that checks is the value is an array and optionally validates each element
   * @param validationElement Optional function to validate each element of the array
   * @returns
   */
  static array(validationElement) {
    return function (value) {
      // Check the JSON is an array
      if (!Array.isArray(value)) {
        return 'Value is not a valid list.';
      }

      ;
      return validationElement ? value.reduce((accum, elementValue) => {
        if (accum) {
          return accum;
        }

        ;
        const resultValidationElement = validationElement(elementValue);

        if (resultValidationElement) {
          return resultValidationElement;
        }

        ;
        return accum;
      }, undefined) : undefined;
    };
  }

  /**
   * Creates a function that checks if the value is equal to list of values
   * @param literals Array of values to compare
   * @returns
   */
  static literal(literals) {
    return function (value) {
      return literals.includes(value) ? undefined : `Invalid value. Allowed values: ${literals.map(String).join(', ')}.`;
    };
  }

}

exports.SettingsValidator = SettingsValidator;
(0, _defineProperty2.default)(SettingsValidator, "filePickerSupportedExtensions", extensions => options => {
  if (typeof options === 'undefined' || typeof options.name === 'undefined') {
    return;
  }

  if (!extensions.includes(_path.default.extname(options.name))) {
    return `File extension is invalid. Allowed file extensions: ${extensions.join(', ')}.`;
  }

  ;
});
(0, _defineProperty2.default)(SettingsValidator, "filePickerFileSize", options => value => {
  if (typeof value === 'undefined' || typeof value.size === 'undefined') {
    return;
  }

  ;

  if (typeof options.minBytes !== 'undefined' && value.size <= options.minBytes) {
    return `File size should be greater or equal than ${options.meaningfulUnit ? (0, _fileSize.formatBytes)(options.minBytes) : `${options.minBytes} bytes`}.`;
  }

  ;

  if (typeof options.maxBytes !== 'undefined' && value.size >= options.maxBytes) {
    return `File size should be lower or equal than ${options.meaningfulUnit ? (0, _fileSize.formatBytes)(options.maxBytes) : `${options.maxBytes} bytes`}.`;
  }

  ;
});
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNldHRpbmdzLXZhbGlkYXRvci50cyJdLCJuYW1lcyI6WyJTZXR0aW5nc1ZhbGlkYXRvciIsImNvbXBvc2UiLCJmdW5jdGlvbnMiLCJjb21wb3NlZFZhbGlkYXRpb24iLCJ2YWx1ZSIsImZuIiwicmVzdWx0IiwibGVuZ3RoIiwiaXNTdHJpbmciLCJ1bmRlZmluZWQiLCJoYXNOb1NwYWNlcyIsInRlc3QiLCJpc05vdEVtcHR5U3RyaW5nIiwibXVsdGlwbGVMaW5lc1N0cmluZyIsIm9wdGlvbnMiLCJsaW5lcyIsInNwbGl0IiwibWF4TGVuZ3RoIiwic29tZSIsImxpbmUiLCJtaW5Sb3dzIiwibWF4Um93cyIsImhhc05vdEludmFsaWRDaGFyYWN0ZXJzIiwiaW52YWxpZENoYXJhY3RlcnMiLCJpbnZhbGlkQ2hhcmFjdGVyIiwiaW5jbHVkZXMiLCJqb2luIiwibm9TdGFydHNXaXRoU3RyaW5nIiwiaW52YWxpZFN0YXJ0aW5nQ2hhcmFjdGVycyIsImludmFsaWRTdGFydGluZ0NoYXJhY3RlciIsInN0YXJ0c1dpdGgiLCJub0xpdGVyYWxTdHJpbmciLCJpbnZhbGlkTGl0ZXJhbHMiLCJpbnZhbGlkTGl0ZXJhbCIsImlzQm9vbGVhbiIsIm51bWJlciIsImludGVnZXIiLCJjaGFyYWN0ZXIiLCJOdW1iZXIiLCJpc0ludGVnZXIiLCJ2YWx1ZU51bWJlciIsIm1pbiIsIm1heCIsImpzb24iLCJ2YWxpZGF0ZVBhcnNlZCIsImpzb25PYmplY3QiLCJKU09OIiwicGFyc2UiLCJlcnJvciIsImFycmF5IiwidmFsaWRhdGlvbkVsZW1lbnQiLCJBcnJheSIsImlzQXJyYXkiLCJyZWR1Y2UiLCJhY2N1bSIsImVsZW1lbnRWYWx1ZSIsInJlc3VsdFZhbGlkYXRpb25FbGVtZW50IiwibGl0ZXJhbCIsImxpdGVyYWxzIiwibWFwIiwiU3RyaW5nIiwiZXh0ZW5zaW9ucyIsIm5hbWUiLCJwYXRoIiwiZXh0bmFtZSIsInNpemUiLCJtaW5CeXRlcyIsIm1lYW5pbmdmdWxVbml0IiwibWF4Qnl0ZXMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O0FBQUE7O0FBQ0E7O0FBRU8sTUFBTUEsaUJBQU4sQ0FBd0I7QUFDN0I7QUFDRjtBQUNBO0FBQ0E7QUFDQTtBQUNnQixTQUFQQyxPQUFPLENBQUMsR0FBR0MsU0FBSixFQUFlO0FBQzNCLFdBQU8sU0FBU0Msa0JBQVQsQ0FBNEJDLEtBQTVCLEVBQW1DO0FBQ3hDLFdBQUssTUFBTUMsRUFBWCxJQUFpQkgsU0FBakIsRUFBNEI7QUFDMUIsY0FBTUksTUFBTSxHQUFHRCxFQUFFLENBQUNELEtBQUQsQ0FBakI7O0FBQ0EsWUFBSSxPQUFPRSxNQUFQLEtBQWtCLFFBQWxCLElBQThCQSxNQUFNLENBQUNDLE1BQVAsR0FBZ0IsQ0FBbEQsRUFBcUQ7QUFDbkQsaUJBQU9ELE1BQVA7QUFDRDs7QUFBQTtBQUNGOztBQUFBO0FBQ0YsS0FQRDtBQVFEOztBQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDaUIsU0FBUkUsUUFBUSxDQUFDSixLQUFELEVBQXFDO0FBQ2xELFdBQU8sT0FBT0EsS0FBUCxLQUFpQixRQUFqQixHQUE0QkssU0FBNUIsR0FBd0Msd0JBQS9DO0FBQ0Q7O0FBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTtBQUNvQixTQUFYQyxXQUFXLENBQUNOLEtBQUQsRUFBb0M7QUFDcEQsV0FBTyxRQUFRTyxJQUFSLENBQWFQLEtBQWIsSUFBc0JLLFNBQXRCLEdBQWtDLHlCQUF6QztBQUNEOztBQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDeUIsU0FBaEJHLGdCQUFnQixDQUFDUixLQUFELEVBQW9DO0FBQ3pELFFBQUksT0FBT0EsS0FBUCxLQUFpQixRQUFyQixFQUErQjtBQUM3QixVQUFJQSxLQUFLLENBQUNHLE1BQU4sS0FBaUIsQ0FBckIsRUFBd0I7QUFDdEIsZUFBTyx5QkFBUDtBQUNELE9BRkQsTUFFTztBQUNMLGVBQU9FLFNBQVA7QUFDRDtBQUNGOztBQUFBO0FBQ0Y7O0FBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTtBQUM0QixTQUFuQkksbUJBQW1CLENBQUNDLE9BQW1FLEdBQUcsRUFBdkUsRUFBMkU7QUFDbkcsV0FBTyxVQUFVVixLQUFWLEVBQXlCO0FBQzlCLFlBQU1XLEtBQUssR0FBR1gsS0FBSyxDQUFDWSxLQUFOLENBQVksWUFBWixFQUEwQlQsTUFBeEM7O0FBQ0EsVUFBSSxPQUFPTyxPQUFPLENBQUNHLFNBQWYsS0FBNkIsV0FBN0IsSUFBNENiLEtBQUssQ0FBQ1ksS0FBTixDQUFZLElBQVosRUFBa0JFLElBQWxCLENBQXVCQyxJQUFJLElBQUlBLElBQUksQ0FBQ1osTUFBTCxHQUFjTyxPQUFPLENBQUNHLFNBQXJELENBQWhELEVBQWlIO0FBQy9HLGVBQVEsbUNBQWtDSCxPQUFPLENBQUNHLFNBQVUsY0FBNUQ7QUFDRDs7QUFBQTs7QUFDRCxVQUFJLE9BQU9ILE9BQU8sQ0FBQ00sT0FBZixLQUEyQixXQUEzQixJQUEwQ0wsS0FBSyxHQUFHRCxPQUFPLENBQUNNLE9BQTlELEVBQXVFO0FBQ3JFLGVBQVEsa0NBQWlDTixPQUFPLENBQUNNLE9BQVEsVUFBekQ7QUFDRDs7QUFBQTs7QUFDRCxVQUFJLE9BQU9OLE9BQU8sQ0FBQ08sT0FBZixLQUEyQixXQUEzQixJQUEwQ04sS0FBSyxHQUFHRCxPQUFPLENBQUNPLE9BQTlELEVBQXVFO0FBQ3JFLGVBQVEsMkNBQTBDUCxPQUFPLENBQUNPLE9BQVEsVUFBbEU7QUFDRDs7QUFBQTtBQUNGLEtBWEQ7QUFZRDs7QUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBO0FBQ2dDLFNBQXZCQyx1QkFBdUIsQ0FBQyxHQUFHQyxpQkFBSixFQUFpQztBQUM3RCxXQUFPLFVBQVVuQixLQUFWLEVBQTZDO0FBQ2xELGFBQU9tQixpQkFBaUIsQ0FBQ0wsSUFBbEIsQ0FBdUJNLGdCQUFnQixJQUFJcEIsS0FBSyxDQUFDcUIsUUFBTixDQUFlRCxnQkFBZixDQUEzQyxJQUNGLHdDQUF1Q0QsaUJBQWlCLENBQUNHLElBQWxCLENBQXVCLElBQXZCLENBQTZCLEdBRGxFLEdBRUhqQixTQUZKO0FBR0QsS0FKRDtBQUtEOztBQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDMkIsU0FBbEJrQixrQkFBa0IsQ0FBQyxHQUFHQyx5QkFBSixFQUF5QztBQUNoRSxXQUFPLFVBQVV4QixLQUFWLEVBQTZDO0FBQ2xELGFBQU93Qix5QkFBeUIsQ0FBQ1YsSUFBMUIsQ0FBK0JXLHdCQUF3QixJQUFJekIsS0FBSyxDQUFDMEIsVUFBTixDQUFpQkQsd0JBQWpCLENBQTNELElBQ0Ysd0JBQXVCRCx5QkFBeUIsQ0FBQ0YsSUFBMUIsQ0FBK0IsSUFBL0IsQ0FBcUMsR0FEMUQsR0FFSGpCLFNBRko7QUFHRCxLQUpEO0FBS0Q7O0FBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTtBQUN3QixTQUFmc0IsZUFBZSxDQUFDLEdBQUdDLGVBQUosRUFBK0I7QUFDbkQsV0FBTyxVQUFVNUIsS0FBVixFQUE2QztBQUNsRCxhQUFPNEIsZUFBZSxDQUFDZCxJQUFoQixDQUFxQmUsY0FBYyxJQUFJN0IsS0FBSyxLQUFLNkIsY0FBakQsSUFDRixnQkFBZUQsZUFBZSxDQUFDTixJQUFoQixDQUFxQixJQUFyQixDQUEyQixHQUR4QyxHQUVIakIsU0FGSjtBQUdELEtBSkQ7QUFLRDs7QUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBO0FBQ2tCLFNBQVR5QixTQUFTLENBQUM5QixLQUFELEVBQW9DO0FBQ2xELFdBQU8sT0FBT0EsS0FBUCxLQUFpQixTQUFqQixHQUNISyxTQURHLEdBRUgsd0RBRko7QUFHRDs7QUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBO0FBQ2UsU0FBTjBCLE1BQU0sQ0FBQ3JCLE9BQTBELEdBQUcsRUFBOUQsRUFBa0U7QUFDN0UsV0FBTyxVQUFVVixLQUFWLEVBQXlCO0FBQzlCLFVBQUlVLE9BQU8sQ0FBQ3NCLE9BQVIsS0FFQSxDQUFDLE9BQU9oQyxLQUFQLEtBQWlCLFFBQWpCLEdBQTRCLENBQUMsR0FBRCxFQUFNLEdBQU4sRUFBV2MsSUFBWCxDQUFnQm1CLFNBQVMsSUFBSWpDLEtBQUssQ0FBQ3FCLFFBQU4sQ0FBZVksU0FBZixDQUE3QixDQUE1QixHQUFzRixLQUF2RixLQUNHLENBQUNDLE1BQU0sQ0FBQ0MsU0FBUCxDQUFpQkQsTUFBTSxDQUFDbEMsS0FBRCxDQUF2QixDQUhKLENBQUosRUFLRTtBQUNBLGVBQU8sOEJBQVA7QUFDRDs7QUFBQTtBQUVELFlBQU1vQyxXQUFXLEdBQUcsT0FBT3BDLEtBQVAsS0FBaUIsUUFBakIsR0FBNEJrQyxNQUFNLENBQUNsQyxLQUFELENBQWxDLEdBQTRDQSxLQUFoRTs7QUFFQSxVQUFJLE9BQU9VLE9BQU8sQ0FBQzJCLEdBQWYsS0FBdUIsV0FBdkIsSUFBc0NELFdBQVcsR0FBRzFCLE9BQU8sQ0FBQzJCLEdBQWhFLEVBQXFFO0FBQ25FLGVBQVEseUNBQXdDM0IsT0FBTyxDQUFDMkIsR0FBSSxHQUE1RDtBQUNEOztBQUFBOztBQUNELFVBQUksT0FBTzNCLE9BQU8sQ0FBQzRCLEdBQWYsS0FBdUIsV0FBdkIsSUFBc0NGLFdBQVcsR0FBRzFCLE9BQU8sQ0FBQzRCLEdBQWhFLEVBQXFFO0FBQ25FLGVBQVEsdUNBQXNDNUIsT0FBTyxDQUFDNEIsR0FBSSxHQUExRDtBQUNEOztBQUFBO0FBQ0YsS0FsQkQ7QUFtQkQ7O0FBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTtBQUNhLFNBQUpDLElBQUksQ0FBQ0MsY0FBRCxFQUFzRDtBQUMvRCxXQUFPLFVBQVV4QyxLQUFWLEVBQXlCO0FBQzlCLFVBQUl5QyxVQUFKLENBRDhCLENBRTlCOztBQUNBLFVBQUk7QUFDRkEsUUFBQUEsVUFBVSxHQUFHQyxJQUFJLENBQUNDLEtBQUwsQ0FBVzNDLEtBQVgsQ0FBYjtBQUNELE9BRkQsQ0FFRSxPQUFPNEMsS0FBUCxFQUFjO0FBQ2QsZUFBTyw2Q0FBUDtBQUNEOztBQUFBO0FBRUQsYUFBT0osY0FBYyxHQUFHQSxjQUFjLENBQUNDLFVBQUQsQ0FBakIsR0FBZ0NwQyxTQUFyRDtBQUNELEtBVkQ7QUFXRDs7QUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBO0FBQ2MsU0FBTHdDLEtBQUssQ0FBQ0MsaUJBQUQsRUFBdUQ7QUFDakUsV0FBTyxVQUFVOUMsS0FBVixFQUE0QjtBQUNqQztBQUNBLFVBQUksQ0FBQytDLEtBQUssQ0FBQ0MsT0FBTixDQUFjaEQsS0FBZCxDQUFMLEVBQTJCO0FBQ3pCLGVBQU8sNEJBQVA7QUFDRDs7QUFBQTtBQUVELGFBQU84QyxpQkFBaUIsR0FDcEI5QyxLQUFLLENBQUNpRCxNQUFOLENBQWEsQ0FBQ0MsS0FBRCxFQUFRQyxZQUFSLEtBQXlCO0FBQ3RDLFlBQUlELEtBQUosRUFBVztBQUNULGlCQUFPQSxLQUFQO0FBQ0Q7O0FBQUE7QUFFRCxjQUFNRSx1QkFBdUIsR0FBR04saUJBQWlCLENBQUNLLFlBQUQsQ0FBakQ7O0FBQ0EsWUFBSUMsdUJBQUosRUFBNkI7QUFDM0IsaUJBQU9BLHVCQUFQO0FBQ0Q7O0FBQUE7QUFFRCxlQUFPRixLQUFQO0FBQ0QsT0FYQyxFQVdDN0MsU0FYRCxDQURvQixHQWFwQkEsU0FiSjtBQWNELEtBcEJEO0FBcUJEOztBQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDZ0IsU0FBUGdELE9BQU8sQ0FBQ0MsUUFBRCxFQUFzQjtBQUNsQyxXQUFPLFVBQVV0RCxLQUFWLEVBQTBDO0FBQy9DLGFBQU9zRCxRQUFRLENBQUNqQyxRQUFULENBQWtCckIsS0FBbEIsSUFBMkJLLFNBQTNCLEdBQXdDLGtDQUFpQ2lELFFBQVEsQ0FBQ0MsR0FBVCxDQUFhQyxNQUFiLEVBQXFCbEMsSUFBckIsQ0FBMEIsSUFBMUIsQ0FBZ0MsR0FBaEg7QUFDRCxLQUZEO0FBR0Q7O0FBNU00Qjs7OzhCQUFsQjFCLGlCLG1DQStNNkI2RCxVQUFELElBQTJCL0MsT0FBRCxJQUErQjtBQUM5RixNQUFJLE9BQU9BLE9BQVAsS0FBbUIsV0FBbkIsSUFBa0MsT0FBT0EsT0FBTyxDQUFDZ0QsSUFBZixLQUF3QixXQUE5RCxFQUEyRTtBQUN6RTtBQUNEOztBQUNELE1BQUksQ0FBQ0QsVUFBVSxDQUFDcEMsUUFBWCxDQUFvQnNDLGNBQUtDLE9BQUwsQ0FBYWxELE9BQU8sQ0FBQ2dELElBQXJCLENBQXBCLENBQUwsRUFBc0Q7QUFDcEQsV0FBUSx1REFBc0RELFVBQVUsQ0FBQ25DLElBQVgsQ0FBZ0IsSUFBaEIsQ0FBc0IsR0FBcEY7QUFDRDs7QUFBQTtBQUNGLEM7OEJBdE5VMUIsaUIsd0JBNE5rQmMsT0FBRCxJQUFrRlYsS0FBRCxJQUE2QjtBQUN4SSxNQUFJLE9BQU9BLEtBQVAsS0FBaUIsV0FBakIsSUFBZ0MsT0FBT0EsS0FBSyxDQUFDNkQsSUFBYixLQUFzQixXQUExRCxFQUF1RTtBQUNyRTtBQUNEOztBQUFBOztBQUNELE1BQUksT0FBT25ELE9BQU8sQ0FBQ29ELFFBQWYsS0FBNEIsV0FBNUIsSUFBMkM5RCxLQUFLLENBQUM2RCxJQUFOLElBQWNuRCxPQUFPLENBQUNvRCxRQUFyRSxFQUErRTtBQUM3RSxXQUFRLDZDQUE0Q3BELE9BQU8sQ0FBQ3FELGNBQVIsR0FBeUIsMkJBQVlyRCxPQUFPLENBQUNvRCxRQUFwQixDQUF6QixHQUEwRCxHQUFFcEQsT0FBTyxDQUFDb0QsUUFBUyxRQUFRLEdBQXpJO0FBQ0Q7O0FBQUE7O0FBQ0QsTUFBSSxPQUFPcEQsT0FBTyxDQUFDc0QsUUFBZixLQUE0QixXQUE1QixJQUEyQ2hFLEtBQUssQ0FBQzZELElBQU4sSUFBY25ELE9BQU8sQ0FBQ3NELFFBQXJFLEVBQStFO0FBQzdFLFdBQVEsMkNBQTBDdEQsT0FBTyxDQUFDcUQsY0FBUixHQUF5QiwyQkFBWXJELE9BQU8sQ0FBQ3NELFFBQXBCLENBQXpCLEdBQTBELEdBQUV0RCxPQUFPLENBQUNzRCxRQUFTLFFBQVEsR0FBdkk7QUFDRDs7QUFBQTtBQUNGLEM7QUFDRiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0IHsgZm9ybWF0Qnl0ZXMgfSBmcm9tICcuL2ZpbGUtc2l6ZSc7XG5cbmV4cG9ydCBjbGFzcyBTZXR0aW5nc1ZhbGlkYXRvciB7XG4gIC8qKlxuICAgKiBDcmVhdGUgYSBmdW5jdGlvbiB0aGF0IGlzIGEgY29tcG9zaXRpb24gb2YgdGhlIGlucHV0IHZhbGlkYXRpb25zXG4gICAqIEBwYXJhbSBmdW5jdGlvbnMgU2V0dGluZ3NWYWxpZGF0b3IgZnVuY3Rpb25zIHRvIGNvbXBvc2VcbiAgICogQHJldHVybnMgY29tcG9zZWQgdmFsaWRhdGlvblxuICAgKi9cbiAgc3RhdGljIGNvbXBvc2UoLi4uZnVuY3Rpb25zKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIGNvbXBvc2VkVmFsaWRhdGlvbih2YWx1ZSkge1xuICAgICAgZm9yIChjb25zdCBmbiBvZiBmdW5jdGlvbnMpIHtcbiAgICAgICAgY29uc3QgcmVzdWx0ID0gZm4odmFsdWUpO1xuICAgICAgICBpZiAodHlwZW9mIHJlc3VsdCA9PT0gJ3N0cmluZycgJiYgcmVzdWx0Lmxlbmd0aCA+IDApIHtcbiAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICB9O1xuICAgICAgfTtcbiAgICB9O1xuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVjayB0aGUgdmFsdWUgaXMgYSBzdHJpbmdcbiAgICogQHBhcmFtIHZhbHVlXG4gICAqIEByZXR1cm5zXG4gICAqL1xuICBzdGF0aWMgaXNTdHJpbmcodmFsdWU6IHVua25vd24pOiBzdHJpbmcgfCB1bmRlZmluZWQge1xuICAgIHJldHVybiB0eXBlb2YgdmFsdWUgPT09ICdzdHJpbmcnID8gdW5kZWZpbmVkIDogXCJWYWx1ZSBpcyBub3QgYSBzdHJpbmcuXCI7XG4gIH07XG5cbiAgLyoqXG4gICAqIENoZWNrIHRoZSBzdHJpbmcgaGFzIG5vIHNwYWNlc1xuICAgKiBAcGFyYW0gdmFsdWVcbiAgICogQHJldHVybnNcbiAgICovXG4gIHN0YXRpYyBoYXNOb1NwYWNlcyh2YWx1ZTogc3RyaW5nKTogc3RyaW5nIHwgdW5kZWZpbmVkIHtcbiAgICByZXR1cm4gL15cXFMqJC8udGVzdCh2YWx1ZSkgPyB1bmRlZmluZWQgOiBcIk5vIHdoaXRlc3BhY2VzIGFsbG93ZWQuXCI7XG4gIH07XG5cbiAgLyoqXG4gICAqIENoZWNrIHRoZSBzdHJpbmcgaGFzIG5vIGVtcHR5XG4gICAqIEBwYXJhbSB2YWx1ZVxuICAgKiBAcmV0dXJuc1xuICAgKi9cbiAgc3RhdGljIGlzTm90RW1wdHlTdHJpbmcodmFsdWU6IHN0cmluZyk6IHN0cmluZyB8IHVuZGVmaW5lZCB7XG4gICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGlmICh2YWx1ZS5sZW5ndGggPT09IDApIHtcbiAgICAgICAgcmV0dXJuIFwiVmFsdWUgY2FuIG5vdCBiZSBlbXB0eS5cIlxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgIH1cbiAgICB9O1xuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVjayB0aGUgbnVtYmVyIG9mIHN0cmluZyBsaW5lcyBpcyBsaW1pdGVkXG4gICAqIEBwYXJhbSBvcHRpb25zXG4gICAqIEByZXR1cm5zXG4gICAqL1xuICBzdGF0aWMgbXVsdGlwbGVMaW5lc1N0cmluZyhvcHRpb25zOiB7IG1pblJvd3M/OiBudW1iZXIsIG1heFJvd3M/OiBudW1iZXIsIG1heExlbmd0aD86IG51bWJlciB9ID0ge30pIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHZhbHVlOiBudW1iZXIpIHtcbiAgICAgIGNvbnN0IGxpbmVzID0gdmFsdWUuc3BsaXQoL1xcclxcbnxcXHJ8XFxuLykubGVuZ3RoO1xuICAgICAgaWYgKHR5cGVvZiBvcHRpb25zLm1heExlbmd0aCAhPT0gJ3VuZGVmaW5lZCcgJiYgdmFsdWUuc3BsaXQoJ1xcbicpLnNvbWUobGluZSA9PiBsaW5lLmxlbmd0aCA+IG9wdGlvbnMubWF4TGVuZ3RoKSkge1xuICAgICAgICByZXR1cm4gYFRoZSBtYXhpbXVtIGxlbmd0aCBvZiBhIGxpbmUgaXMgJHtvcHRpb25zLm1heExlbmd0aH0gY2hhcmFjdGVycy5gO1xuICAgICAgfTtcbiAgICAgIGlmICh0eXBlb2Ygb3B0aW9ucy5taW5Sb3dzICE9PSAndW5kZWZpbmVkJyAmJiBsaW5lcyA8IG9wdGlvbnMubWluUm93cykge1xuICAgICAgICByZXR1cm4gYFRoZSBzdHJpbmcgc2hvdWxkIGhhdmUgbW9yZSBvciAke29wdGlvbnMubWluUm93c30gbGluZS9zLmA7XG4gICAgICB9O1xuICAgICAgaWYgKHR5cGVvZiBvcHRpb25zLm1heFJvd3MgIT09ICd1bmRlZmluZWQnICYmIGxpbmVzID4gb3B0aW9ucy5tYXhSb3dzKSB7XG4gICAgICAgIHJldHVybiBgVGhlIHN0cmluZyBzaG91bGQgaGF2ZSBsZXNzIG9yIGVxdWFsIHRvICR7b3B0aW9ucy5tYXhSb3dzfSBsaW5lL3MuYDtcbiAgICAgIH07XG4gICAgfVxuICB9O1xuXG4gIC8qKlxuICAgKiBDcmVhdGVzIGEgZnVuY3Rpb24gdGhhdCBjaGVja3MgdGhlIHN0cmluZyBkb2VzIG5vdCBjb250YWluIHNvbWUgY2hhcmFjdGVyc1xuICAgKiBAcGFyYW0gaW52YWxpZENoYXJhY3RlcnNcbiAgICogQHJldHVybnNcbiAgICovXG4gIHN0YXRpYyBoYXNOb3RJbnZhbGlkQ2hhcmFjdGVycyguLi5pbnZhbGlkQ2hhcmFjdGVyczogc3RyaW5nW10pIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHZhbHVlOiBzdHJpbmcpOiBzdHJpbmcgfCB1bmRlZmluZWQge1xuICAgICAgcmV0dXJuIGludmFsaWRDaGFyYWN0ZXJzLnNvbWUoaW52YWxpZENoYXJhY3RlciA9PiB2YWx1ZS5pbmNsdWRlcyhpbnZhbGlkQ2hhcmFjdGVyKSlcbiAgICAgICAgPyBgSXQgY2FuJ3QgY29udGFpbiBpbnZhbGlkIGNoYXJhY3RlcnM6ICR7aW52YWxpZENoYXJhY3RlcnMuam9pbignLCAnKX0uYFxuICAgICAgICA6IHVuZGVmaW5lZDtcbiAgICB9O1xuICB9O1xuXG4gIC8qKlxuICAgKiBDcmVhdGVzIGEgZnVuY3Rpb24gdGhhdCBjaGVja3MgdGhlIHN0cmluZyBkb2VzIG5vdCBzdGFydCB3aXRoIGEgc3Vic3RyaW5nXG4gICAqIEBwYXJhbSBpbnZhbGlkU3RhcnRpbmdDaGFyYWN0ZXJzXG4gICAqIEByZXR1cm5zXG4gICAqL1xuICBzdGF0aWMgbm9TdGFydHNXaXRoU3RyaW5nKC4uLmludmFsaWRTdGFydGluZ0NoYXJhY3RlcnM6IHN0cmluZ1tdKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZTogc3RyaW5nKTogc3RyaW5nIHwgdW5kZWZpbmVkIHtcbiAgICAgIHJldHVybiBpbnZhbGlkU3RhcnRpbmdDaGFyYWN0ZXJzLnNvbWUoaW52YWxpZFN0YXJ0aW5nQ2hhcmFjdGVyID0+IHZhbHVlLnN0YXJ0c1dpdGgoaW52YWxpZFN0YXJ0aW5nQ2hhcmFjdGVyKSlcbiAgICAgICAgPyBgSXQgY2FuJ3Qgc3RhcnQgd2l0aDogJHtpbnZhbGlkU3RhcnRpbmdDaGFyYWN0ZXJzLmpvaW4oJywgJyl9LmBcbiAgICAgICAgOiB1bmRlZmluZWQ7XG4gICAgfTtcbiAgfTtcblxuICAvKipcbiAgICogQ3JlYXRlcyBhIGZ1bmN0aW9uIHRoYXQgY2hlY2tzIHRoZSBzdHJpbmcgaXMgbm90IGVxdWFscyB0byBzb21lIHZhbHVlc1xuICAgKiBAcGFyYW0gaW52YWxpZExpdGVyYWxzXG4gICAqIEByZXR1cm5zXG4gICAqL1xuICBzdGF0aWMgbm9MaXRlcmFsU3RyaW5nKC4uLmludmFsaWRMaXRlcmFsczogc3RyaW5nW10pIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHZhbHVlOiBzdHJpbmcpOiBzdHJpbmcgfCB1bmRlZmluZWQge1xuICAgICAgcmV0dXJuIGludmFsaWRMaXRlcmFscy5zb21lKGludmFsaWRMaXRlcmFsID0+IHZhbHVlID09PSBpbnZhbGlkTGl0ZXJhbClcbiAgICAgICAgPyBgSXQgY2FuJ3QgYmU6ICR7aW52YWxpZExpdGVyYWxzLmpvaW4oJywgJyl9LmBcbiAgICAgICAgOiB1bmRlZmluZWQ7XG4gICAgfTtcbiAgfTtcblxuICAvKipcbiAgICogQ2hlY2sgdGhlIHZhbHVlIGlzIGEgYm9vbGVhblxuICAgKiBAcGFyYW0gdmFsdWVcbiAgICogQHJldHVybnNcbiAgICovXG4gIHN0YXRpYyBpc0Jvb2xlYW4odmFsdWU6IHN0cmluZyk6IHN0cmluZyB8IHVuZGVmaW5lZCB7XG4gICAgcmV0dXJuIHR5cGVvZiB2YWx1ZSA9PT0gJ2Jvb2xlYW4nXG4gICAgICA/IHVuZGVmaW5lZFxuICAgICAgOiBcIkl0IHNob3VsZCBiZSBhIGJvb2xlYW4uIEFsbG93ZWQgdmFsdWVzOiB0cnVlIG9yIGZhbHNlLlwiO1xuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVjayB0aGUgdmFsdWUgaXMgYSBudW1iZXIgYmV0d2VlbiBzb21lIG9wdGlvbmFsIGxpbWl0c1xuICAgKiBAcGFyYW0gb3B0aW9uc1xuICAgKiBAcmV0dXJuc1xuICAgKi9cbiAgc3RhdGljIG51bWJlcihvcHRpb25zOiB7IG1pbj86IG51bWJlciwgbWF4PzogbnVtYmVyLCBpbnRlZ2VyPzogYm9vbGVhbiB9ID0ge30pIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHZhbHVlOiBudW1iZXIpIHtcbiAgICAgIGlmIChvcHRpb25zLmludGVnZXJcbiAgICAgICAgJiYgKFxuICAgICAgICAgICh0eXBlb2YgdmFsdWUgPT09ICdzdHJpbmcnID8gWycuJywgJywnXS5zb21lKGNoYXJhY3RlciA9PiB2YWx1ZS5pbmNsdWRlcyhjaGFyYWN0ZXIpKSA6IGZhbHNlKVxuICAgICAgICAgIHx8ICFOdW1iZXIuaXNJbnRlZ2VyKE51bWJlcih2YWx1ZSkpXG4gICAgICAgIClcbiAgICAgICkge1xuICAgICAgICByZXR1cm4gJ051bWJlciBzaG91bGQgYmUgYW4gaW50ZWdlci4nXG4gICAgICB9O1xuXG4gICAgICBjb25zdCB2YWx1ZU51bWJlciA9IHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycgPyBOdW1iZXIodmFsdWUpIDogdmFsdWU7XG5cbiAgICAgIGlmICh0eXBlb2Ygb3B0aW9ucy5taW4gIT09ICd1bmRlZmluZWQnICYmIHZhbHVlTnVtYmVyIDwgb3B0aW9ucy5taW4pIHtcbiAgICAgICAgcmV0dXJuIGBWYWx1ZSBzaG91bGQgYmUgZ3JlYXRlciBvciBlcXVhbCB0aGFuICR7b3B0aW9ucy5taW59LmA7XG4gICAgICB9O1xuICAgICAgaWYgKHR5cGVvZiBvcHRpb25zLm1heCAhPT0gJ3VuZGVmaW5lZCcgJiYgdmFsdWVOdW1iZXIgPiBvcHRpb25zLm1heCkge1xuICAgICAgICByZXR1cm4gYFZhbHVlIHNob3VsZCBiZSBsb3dlciBvciBlcXVhbCB0aGFuICR7b3B0aW9ucy5tYXh9LmA7XG4gICAgICB9O1xuICAgIH07XG4gIH07XG5cbiAgLyoqXG4gICAqIENyZWF0ZXMgYSBmdW5jdGlvbiB0aGF0IGNoZWNrcyBpZiB0aGUgdmFsdWUgaXMgYSBqc29uXG4gICAqIEBwYXJhbSB2YWxpZGF0ZVBhcnNlZCBPcHRpb25hbCBwYXJhbWV0ZXIgdG8gdmFsaWRhdGUgdGhlIHBhcnNlZCBvYmplY3RcbiAgICogQHJldHVybnNcbiAgICovXG4gIHN0YXRpYyBqc29uKHZhbGlkYXRlUGFyc2VkOiAob2JqZWN0OiBhbnkpID0+IHN0cmluZyB8IHVuZGVmaW5lZCkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodmFsdWU6IHN0cmluZykge1xuICAgICAgbGV0IGpzb25PYmplY3Q7XG4gICAgICAvLyBUcnkgdG8gcGFyc2UgdGhlIHN0cmluZyBhcyBKU09OXG4gICAgICB0cnkge1xuICAgICAgICBqc29uT2JqZWN0ID0gSlNPTi5wYXJzZSh2YWx1ZSk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICByZXR1cm4gXCJWYWx1ZSBjYW4ndCBiZSBwYXJzZWQuIFRoZXJlIGlzIHNvbWUgZXJyb3IuXCI7XG4gICAgICB9O1xuXG4gICAgICByZXR1cm4gdmFsaWRhdGVQYXJzZWQgPyB2YWxpZGF0ZVBhcnNlZChqc29uT2JqZWN0KSA6IHVuZGVmaW5lZDtcbiAgICB9O1xuICB9O1xuXG4gIC8qKlxuICAgKiBDcmVhdGVzIGEgZnVuY3Rpb24gdGhhdCBjaGVja3MgaXMgdGhlIHZhbHVlIGlzIGFuIGFycmF5IGFuZCBvcHRpb25hbGx5IHZhbGlkYXRlcyBlYWNoIGVsZW1lbnRcbiAgICogQHBhcmFtIHZhbGlkYXRpb25FbGVtZW50IE9wdGlvbmFsIGZ1bmN0aW9uIHRvIHZhbGlkYXRlIGVhY2ggZWxlbWVudCBvZiB0aGUgYXJyYXlcbiAgICogQHJldHVybnNcbiAgICovXG4gIHN0YXRpYyBhcnJheSh2YWxpZGF0aW9uRWxlbWVudDogKGpzb246IGFueSkgPT4gc3RyaW5nIHwgdW5kZWZpbmVkKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZTogdW5rbm93bltdKSB7XG4gICAgICAvLyBDaGVjayB0aGUgSlNPTiBpcyBhbiBhcnJheVxuICAgICAgaWYgKCFBcnJheS5pc0FycmF5KHZhbHVlKSkge1xuICAgICAgICByZXR1cm4gJ1ZhbHVlIGlzIG5vdCBhIHZhbGlkIGxpc3QuJztcbiAgICAgIH07XG5cbiAgICAgIHJldHVybiB2YWxpZGF0aW9uRWxlbWVudFxuICAgICAgICA/IHZhbHVlLnJlZHVjZSgoYWNjdW0sIGVsZW1lbnRWYWx1ZSkgPT4ge1xuICAgICAgICAgIGlmIChhY2N1bSkge1xuICAgICAgICAgICAgcmV0dXJuIGFjY3VtO1xuICAgICAgICAgIH07XG5cbiAgICAgICAgICBjb25zdCByZXN1bHRWYWxpZGF0aW9uRWxlbWVudCA9IHZhbGlkYXRpb25FbGVtZW50KGVsZW1lbnRWYWx1ZSk7XG4gICAgICAgICAgaWYgKHJlc3VsdFZhbGlkYXRpb25FbGVtZW50KSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzdWx0VmFsaWRhdGlvbkVsZW1lbnQ7XG4gICAgICAgICAgfTtcblxuICAgICAgICAgIHJldHVybiBhY2N1bTtcbiAgICAgICAgfSwgdW5kZWZpbmVkKVxuICAgICAgICA6IHVuZGVmaW5lZDtcbiAgICB9O1xuICB9O1xuXG4gIC8qKlxuICAgKiBDcmVhdGVzIGEgZnVuY3Rpb24gdGhhdCBjaGVja3MgaWYgdGhlIHZhbHVlIGlzIGVxdWFsIHRvIGxpc3Qgb2YgdmFsdWVzXG4gICAqIEBwYXJhbSBsaXRlcmFscyBBcnJheSBvZiB2YWx1ZXMgdG8gY29tcGFyZVxuICAgKiBAcmV0dXJuc1xuICAgKi9cbiAgc3RhdGljIGxpdGVyYWwobGl0ZXJhbHM6IHVua25vd25bXSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodmFsdWU6IGFueSk6IHN0cmluZyB8IHVuZGVmaW5lZCB7XG4gICAgICByZXR1cm4gbGl0ZXJhbHMuaW5jbHVkZXModmFsdWUpID8gdW5kZWZpbmVkIDogYEludmFsaWQgdmFsdWUuIEFsbG93ZWQgdmFsdWVzOiAke2xpdGVyYWxzLm1hcChTdHJpbmcpLmpvaW4oJywgJyl9LmA7XG4gICAgfTtcbiAgfTtcblxuICAvLyBGaWxlUGlja2VyXG4gIHN0YXRpYyBmaWxlUGlja2VyU3VwcG9ydGVkRXh0ZW5zaW9ucyA9IChleHRlbnNpb25zOiBzdHJpbmdbXSkgPT4gKG9wdGlvbnM6IHsgbmFtZTogc3RyaW5nIH0pID0+IHtcbiAgICBpZiAodHlwZW9mIG9wdGlvbnMgPT09ICd1bmRlZmluZWQnIHx8IHR5cGVvZiBvcHRpb25zLm5hbWUgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmICghZXh0ZW5zaW9ucy5pbmNsdWRlcyhwYXRoLmV4dG5hbWUob3B0aW9ucy5uYW1lKSkpIHtcbiAgICAgIHJldHVybiBgRmlsZSBleHRlbnNpb24gaXMgaW52YWxpZC4gQWxsb3dlZCBmaWxlIGV4dGVuc2lvbnM6ICR7ZXh0ZW5zaW9ucy5qb2luKCcsICcpfS5gO1xuICAgIH07XG4gIH07XG5cbiAgLyoqXG4gICAqIGZpbGVQaWNrZXJGaWxlU2l6ZVxuICAgKiBAcGFyYW0gb3B0aW9uc1xuICAgKi9cbiAgc3RhdGljIGZpbGVQaWNrZXJGaWxlU2l6ZSA9IChvcHRpb25zOiB7IG1heEJ5dGVzPzogbnVtYmVyLCBtaW5CeXRlcz86IG51bWJlciwgbWVhbmluZ2Z1bFVuaXQ/OiBib29sZWFuIH0pID0+ICh2YWx1ZTogeyBzaXplOiBudW1iZXIgfSkgPT4ge1xuICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICd1bmRlZmluZWQnIHx8IHR5cGVvZiB2YWx1ZS5zaXplID09PSAndW5kZWZpbmVkJykge1xuICAgICAgcmV0dXJuO1xuICAgIH07XG4gICAgaWYgKHR5cGVvZiBvcHRpb25zLm1pbkJ5dGVzICE9PSAndW5kZWZpbmVkJyAmJiB2YWx1ZS5zaXplIDw9IG9wdGlvbnMubWluQnl0ZXMpIHtcbiAgICAgIHJldHVybiBgRmlsZSBzaXplIHNob3VsZCBiZSBncmVhdGVyIG9yIGVxdWFsIHRoYW4gJHtvcHRpb25zLm1lYW5pbmdmdWxVbml0ID8gZm9ybWF0Qnl0ZXMob3B0aW9ucy5taW5CeXRlcykgOiBgJHtvcHRpb25zLm1pbkJ5dGVzfSBieXRlc2B9LmA7XG4gICAgfTtcbiAgICBpZiAodHlwZW9mIG9wdGlvbnMubWF4Qnl0ZXMgIT09ICd1bmRlZmluZWQnICYmIHZhbHVlLnNpemUgPj0gb3B0aW9ucy5tYXhCeXRlcykge1xuICAgICAgcmV0dXJuIGBGaWxlIHNpemUgc2hvdWxkIGJlIGxvd2VyIG9yIGVxdWFsIHRoYW4gJHtvcHRpb25zLm1lYW5pbmdmdWxVbml0ID8gZm9ybWF0Qnl0ZXMob3B0aW9ucy5tYXhCeXRlcykgOiBgJHtvcHRpb25zLm1heEJ5dGVzfSBieXRlc2B9LmA7XG4gICAgfTtcbiAgfTtcbn07XG4iXX0=