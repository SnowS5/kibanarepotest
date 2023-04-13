"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ReportPrinter = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _fs = _interopRequireDefault(require("fs"));

var _path = _interopRequireDefault(require("path"));

var _printer = _interopRequireDefault(require("pdfmake/src/printer"));

var _clockIconRaw = _interopRequireDefault(require("./clock-icon-raw"));

var _filterIconRaw = _interopRequireDefault(require("./filter-icon-raw"));

var _visualizations = require("../../integration-files/visualizations");

var _logger = require("../logger");

var TimSort = _interopRequireWildcard(require("timsort"));

var _getConfiguration = require("../get-configuration");

var _constants = require("../../../common/constants");

var _settings = require("../../../common/services/settings");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

const COLORS = {
  PRIMARY: _constants.REPORTS_PRIMARY_COLOR
};

const pageConfiguration = ({
  pathToLogo,
  pageHeader,
  pageFooter
}) => ({
  styles: {
    h1: {
      fontSize: 22,
      monslight: true,
      color: COLORS.PRIMARY
    },
    h2: {
      fontSize: 18,
      monslight: true,
      color: COLORS.PRIMARY
    },
    h3: {
      fontSize: 16,
      monslight: true,
      color: COLORS.PRIMARY
    },
    h4: {
      fontSize: 14,
      monslight: true,
      color: COLORS.PRIMARY
    },
    standard: {
      color: '#333'
    },
    whiteColorFilters: {
      color: '#FFF',
      fontSize: 14
    },
    whiteColor: {
      color: '#FFF'
    }
  },
  pageMargins: [40, 80, 40, 80],
  header: {
    margin: [40, 20, 0, 0],
    columns: [{
      image: _path.default.join(__dirname, `../../../public/assets/${pathToLogo}`),
      fit: [190, 50]
    }, {
      text: pageHeader,
      alignment: 'right',
      margin: [0, 0, 40, 0],
      color: COLORS.PRIMARY,
      width: 'auto'
    }]
  },
  content: [],

  footer(currentPage, pageCount) {
    return {
      columns: [{
        text: pageFooter,
        color: COLORS.PRIMARY,
        margin: [40, 40, 0, 0]
      }, {
        text: 'Page ' + currentPage.toString() + ' of ' + pageCount,
        alignment: 'right',
        margin: [0, 40, 40, 0],
        color: COLORS.PRIMARY,
        width: 'auto'
      }]
    };
  },

  pageBreakBefore(currentNode, followingNodesOnPage) {
    if (currentNode.id && currentNode.id.includes('splitvis')) {
      return followingNodesOnPage.length === 6 || followingNodesOnPage.length === 7;
    }

    if (currentNode.id && currentNode.id.includes('splitsinglevis') || currentNode.id && currentNode.id.includes('singlevis')) {
      return followingNodesOnPage.length === 6;
    }

    return false;
  }

});

const fonts = {
  Roboto: {
    normal: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/OpenSans-Light.ttf'),
    bold: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/OpenSans-Bold.ttf'),
    italics: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/OpenSans-Italic.ttf'),
    bolditalics: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/OpenSans-BoldItalic.ttf'),
    monslight: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/Montserrat-Light.ttf')
  }
};

class ReportPrinter {
  constructor() {
    (0, _defineProperty2.default)(this, "_content", void 0);
    (0, _defineProperty2.default)(this, "_printer", void 0);
    this._printer = new _printer.default(fonts);
    this._content = [];
  }

  addContent(...content) {
    this._content.push(...content);

    return this;
  }

  addConfigTables(tables) {
    (0, _logger.log)('reporting:renderConfigTables', 'Started to render configuration tables', 'info');
    (0, _logger.log)('reporting:renderConfigTables', `tables: ${tables.length}`, 'debug');

    for (const table of tables) {
      let rowsparsed = table.rows;

      if (Array.isArray(rowsparsed) && rowsparsed.length) {
        const rows = rowsparsed.length > 100 ? rowsparsed.slice(0, 99) : rowsparsed;
        this.addContent({
          text: table.title,
          style: {
            fontSize: 11,
            color: '#000'
          },
          margin: table.title && table.type === 'table' ? [0, 0, 0, 5] : ''
        });

        if (table.title === 'Monitored directories') {
          this.addContent({
            text: 'RT: Real time | WD: Who-data | Per.: Permission | MT: Modification time | SL: Symbolic link | RL: Recursion level',
            style: {
              fontSize: 8,
              color: COLORS.PRIMARY
            },
            margin: [0, 0, 0, 5]
          });
        }

        const full_body = [];
        const modifiedRows = rows.map(row => row.map(cell => ({
          text: cell || '-',
          style: 'standard'
        }))); // for (const row of rows) {
        //   modifiedRows.push(
        //     row.map(cell => ({ text: cell || '-', style: 'standard' }))
        //   );
        // }

        let widths = [];
        widths = Array(table.columns.length - 1).fill('auto');
        widths.push('*');

        if (table.type === 'config') {
          full_body.push(table.columns.map(col => ({
            text: col || '-',
            border: [0, 0, 0, 20],
            fontSize: 0,
            colSpan: 2
          })), ...modifiedRows);
          this.addContent({
            fontSize: 8,
            table: {
              headerRows: 0,
              widths,
              body: full_body,
              dontBreakRows: true
            },
            layout: {
              fillColor: i => i === 0 ? '#fff' : null,
              hLineColor: () => '#D3DAE6',
              hLineWidth: () => 1,
              vLineWidth: () => 0
            }
          });
        } else if (table.type === 'table') {
          full_body.push(table.columns.map(col => ({
            text: col || '-',
            style: 'whiteColor',
            border: [0, 0, 0, 0]
          })), ...modifiedRows);
          this.addContent({
            fontSize: 8,
            table: {
              headerRows: 1,
              widths,
              body: full_body
            },
            layout: {
              fillColor: i => i === 0 ? COLORS.PRIMARY : null,
              hLineColor: () => COLORS.PRIMARY,
              hLineWidth: () => 1,
              vLineWidth: () => 0
            }
          });
        }

        this.addNewLine();
      }

      (0, _logger.log)('reporting:renderConfigTables', `Table rendered`, 'debug');
    }
  }

  addTables(tables) {
    (0, _logger.log)('reporting:renderTables', 'Started to render tables', 'info');
    (0, _logger.log)('reporting:renderTables', `tables: ${tables.length}`, 'debug');

    for (const table of tables) {
      let rowsparsed = [];
      rowsparsed = table.rows;

      if (Array.isArray(rowsparsed) && rowsparsed.length) {
        const rows = rowsparsed.length > 100 ? rowsparsed.slice(0, 99) : rowsparsed;
        this.addContent({
          text: table.title,
          style: 'h3',
          pageBreak: 'before',
          pageOrientation: table.columns.length >= 9 ? 'landscape' : 'portrait'
        });
        this.addNewLine();
        const full_body = [];

        const sortTableRows = (a, b) => parseInt(a[a.length - 1]) < parseInt(b[b.length - 1]) ? 1 : parseInt(a[a.length - 1]) > parseInt(b[b.length - 1]) ? -1 : 0;

        TimSort.sort(rows, sortTableRows);
        const modifiedRows = rows.map(row => row.map(cell => ({
          text: cell || '-',
          style: 'standard'
        }))); // the width of the columns is assigned

        const widths = Array(table.columns.length - 1).fill('auto');
        widths.push('*');
        full_body.push(table.columns.map(col => ({
          text: col || '-',
          style: 'whiteColor',
          border: [0, 0, 0, 0]
        })), ...modifiedRows);
        this.addContent({
          fontSize: 8,
          table: {
            headerRows: 1,
            widths,
            body: full_body
          },
          layout: {
            fillColor: i => i === 0 ? COLORS.PRIMARY : null,
            hLineColor: () => COLORS.PRIMARY,
            hLineWidth: () => 1,
            vLineWidth: () => 0
          }
        });
        this.addNewLine();
        (0, _logger.log)('reporting:renderTables', `Table rendered`, 'debug');
      }
    }
  }

  addTimeRangeAndFilters(from, to, filters, timeZone) {
    (0, _logger.log)('reporting:renderTimeRangeAndFilters', `Started to render the time range and the filters`, 'info');
    (0, _logger.log)('reporting:renderTimeRangeAndFilters', `from: ${from}, to: ${to}, filters: ${filters}, timeZone: ${timeZone}`, 'debug');
    const fromDate = new Date(new Date(from).toLocaleString('en-US', {
      timeZone
    }));
    const toDate = new Date(new Date(to).toLocaleString('en-US', {
      timeZone
    }));
    const str = `${this.formatDate(fromDate)} to ${this.formatDate(toDate)}`;
    this.addContent({
      fontSize: 8,
      table: {
        widths: ['*'],
        body: [[{
          columns: [{
            svg: _clockIconRaw.default,
            width: 10,
            height: 10,
            margin: [40, 5, 0, 0]
          }, {
            text: str || '-',
            margin: [43, 0, 0, 0],
            style: 'whiteColorFilters'
          }]
        }], [{
          columns: [{
            svg: _filterIconRaw.default,
            width: 10,
            height: 10,
            margin: [40, 6, 0, 0]
          }, {
            text: filters || '-',
            margin: [43, 0, 0, 0],
            style: 'whiteColorFilters'
          }]
        }]]
      },
      margin: [-40, 0, -40, 0],
      layout: {
        fillColor: () => COLORS.PRIMARY,
        hLineWidth: () => 0,
        vLineWidth: () => 0
      }
    });
    this.addContent({
      text: '\n'
    });
    (0, _logger.log)('reporting:renderTimeRangeAndFilters', 'Time range and filters rendered', 'debug');
  }

  addVisualizations(visualizations, isAgents, tab) {
    (0, _logger.log)('reporting:renderVisualizations', `${visualizations.length} visualizations for tab ${tab}`, 'info');
    const single_vis = visualizations.filter(item => item.width >= 600);
    const double_vis = visualizations.filter(item => item.width < 600);
    single_vis.forEach(visualization => {
      const title = this.checkTitle(visualization, isAgents, tab);
      this.addContent({
        id: 'singlevis' + title[0]._source.title,
        text: title[0]._source.title,
        style: 'h3'
      });
      this.addContent({
        columns: [{
          image: visualization.element,
          width: 500
        }]
      });
      this.addNewLine();
    });
    let pair = [];

    for (const item of double_vis) {
      pair.push(item);

      if (pair.length === 2) {
        const title_1 = this.checkTitle(pair[0], isAgents, tab);
        const title_2 = this.checkTitle(pair[1], isAgents, tab);
        this.addContent({
          columns: [{
            id: 'splitvis' + title_1[0]._source.title,
            text: title_1[0]._source.title,
            style: 'h3',
            width: 280
          }, {
            id: 'splitvis' + title_2[0]._source.title,
            text: title_2[0]._source.title,
            style: 'h3',
            width: 280
          }]
        });
        this.addContent({
          columns: [{
            image: pair[0].element,
            width: 270
          }, {
            image: pair[1].element,
            width: 270
          }]
        });
        this.addNewLine();
        pair = [];
      }
    }

    if (double_vis.length % 2 !== 0) {
      const item = double_vis[double_vis.length - 1];
      const title = this.checkTitle(item, isAgents, tab);
      this.addContent({
        columns: [{
          id: 'splitsinglevis' + title[0]._source.title,
          text: title[0]._source.title,
          style: 'h3',
          width: 280
        }]
      });
      this.addContent({
        columns: [{
          image: item.element,
          width: 280
        }]
      });
      this.addNewLine();
    }
  }

  formatDate(date) {
    (0, _logger.log)('reporting:formatDate', `Format date ${date}`, 'info');
    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();
    const hours = date.getHours();
    const minutes = date.getMinutes();
    const seconds = date.getSeconds();
    const str = `${year}-${month < 10 ? '0' + month : month}-${day < 10 ? '0' + day : day}T${hours < 10 ? '0' + hours : hours}:${minutes < 10 ? '0' + minutes : minutes}:${seconds < 10 ? '0' + seconds : seconds}`;
    (0, _logger.log)('reporting:formatDate', `str: ${str}`, 'debug');
    return str;
  }

  checkTitle(item, isAgents, tab) {
    (0, _logger.log)('reporting:checkTitle', `Item ID ${item.id}, from ${isAgents ? 'agents' : 'overview'} and tab ${tab}`, 'info');
    const title = isAgents ? _visualizations.AgentsVisualizations[tab].filter(v => v._id === item.id) : _visualizations.OverviewVisualizations[tab].filter(v => v._id === item.id);
    return title;
  }

  addSimpleTable({
    columns,
    items,
    title
  }) {
    if (title) {
      this.addContent(typeof title === 'string' ? {
        text: title,
        style: 'h4'
      } : title).addNewLine();
    }

    if (!items || !items.length) {
      this.addContent({
        text: 'No results match your search criteria',
        style: 'standard'
      });
      return this;
    }

    const tableHeader = columns.map(column => {
      return {
        text: column.label,
        style: 'whiteColor',
        border: [0, 0, 0, 0]
      };
    });
    const tableRows = items.map((item, index) => {
      return columns.map(column => {
        const cellValue = item[column.id];
        return {
          text: typeof cellValue !== 'undefined' ? cellValue : '-',
          style: 'standard'
        };
      });
    }); // 385 is the max initial width per column

    let totalLength = columns.length - 1;
    const widthColumn = 385 / totalLength;
    let totalWidth = totalLength * widthColumn;
    const widths = [];

    for (let step = 0; step < columns.length - 1; step++) {
      let columnLength = this.getColumnWidth(columns[step], tableRows, step);

      if (columnLength <= Math.round(totalWidth / totalLength)) {
        widths.push(columnLength);
        totalWidth -= columnLength;
      } else {
        widths.push(Math.round(totalWidth / totalLength));
        totalWidth -= Math.round(totalWidth / totalLength);
      }

      totalLength--;
    }

    widths.push('*');
    this.addContent({
      fontSize: 8,
      table: {
        headerRows: 1,
        widths,
        body: [tableHeader, ...tableRows]
      },
      layout: {
        fillColor: i => i === 0 ? COLORS.PRIMARY : null,
        hLineColor: () => COLORS.PRIMARY,
        hLineWidth: () => 1,
        vLineWidth: () => 0
      }
    }).addNewLine();
    return this;
  }

  addList({
    title,
    list
  }) {
    return this.addContentWithNewLine(typeof title === 'string' ? {
      text: title,
      style: 'h2'
    } : title).addContent({
      ul: list.filter(element => element)
    }).addNewLine();
  }

  addNewLine() {
    return this.addContent({
      text: '\n'
    });
  }

  addContentWithNewLine(title) {
    return this.addContent(title).addNewLine();
  }

  addAgentsFilters(agents) {
    (0, _logger.log)('reporting:addAgentsFilters', `Started to render the authorized agents filters`, 'info');
    (0, _logger.log)('reporting:addAgentsFilters', `agents: ${agents}`, 'debug');
    this.addNewLine();
    this.addContent({
      text: 'NOTE: This report only includes the authorized agents of the user who generated the report',
      style: {
        fontSize: 10,
        color: COLORS.PRIMARY
      },
      margin: [0, 0, 0, 5]
    });
    /*TODO: This will be enabled by a config*/

    /* this.addContent({
      fontSize: 8,
      table: {
        widths: ['*'],
        body: [
          [
            {
              columns: [
                {
                  svg: filterIconRaw,
                  width: 10,
                  height: 10,
                  margin: [40, 6, 0, 0]
                },
                {
                  text: `Agent IDs: ${agents}` || '-',
                  margin: [43, 0, 0, 0],
                  style: { fontSize: 8, color: '#333' }
                }
              ]
            }
          ]
        ]
      },
      margin: [-40, 0, -40, 0],
      layout: {
        fillColor: () => null,
        hLineWidth: () => 0,
        vLineWidth: () => 0
      }
    }); */

    this.addContent({
      text: '\n'
    });
    (0, _logger.log)('reporting:addAgentsFilters', 'Time range and filters rendered', 'debug');
  }

  async print(reportPath) {
    return new Promise((resolve, reject) => {
      try {
        const configuration = (0, _getConfiguration.getConfiguration)();
        const pathToLogo = (0, _settings.getCustomizationSetting)(configuration, 'customization.logo.reports');
        const pageHeader = (0, _settings.getCustomizationSetting)(configuration, 'customization.reports.header');
        const pageFooter = (0, _settings.getCustomizationSetting)(configuration, 'customization.reports.footer');

        const document = this._printer.createPdfKitDocument({ ...pageConfiguration({
            pathToLogo,
            pageHeader,
            pageFooter
          }),
          content: this._content
        });

        document.on('error', reject);
        document.on('end', resolve);
        document.pipe(_fs.default.createWriteStream(reportPath));
        document.end();
      } catch (ex) {
        reject(ex);
      }
    });
  }
  /**
   * Returns the width of a given column
   *
   * @param column
   * @param tableRows
   * @param step
   * @returns {number}
   */


  getColumnWidth(column, tableRows, index) {
    const widthCharacter = 5; //min width per character
    //Get the longest row value

    const maxRowLength = tableRows.reduce((maxLength, row) => {
      return row[index].text.length > maxLength ? row[index].text.length : maxLength;
    }, 0); //Get column name length

    const headerLength = column.label.length; //Use the longest to get the column width

    const maxLength = maxRowLength > headerLength ? maxRowLength : headerLength;
    return maxLength * widthCharacter;
  }

}

exports.ReportPrinter = ReportPrinter;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInByaW50ZXIudHMiXSwibmFtZXMiOlsiQ09MT1JTIiwiUFJJTUFSWSIsIlJFUE9SVFNfUFJJTUFSWV9DT0xPUiIsInBhZ2VDb25maWd1cmF0aW9uIiwicGF0aFRvTG9nbyIsInBhZ2VIZWFkZXIiLCJwYWdlRm9vdGVyIiwic3R5bGVzIiwiaDEiLCJmb250U2l6ZSIsIm1vbnNsaWdodCIsImNvbG9yIiwiaDIiLCJoMyIsImg0Iiwic3RhbmRhcmQiLCJ3aGl0ZUNvbG9yRmlsdGVycyIsIndoaXRlQ29sb3IiLCJwYWdlTWFyZ2lucyIsImhlYWRlciIsIm1hcmdpbiIsImNvbHVtbnMiLCJpbWFnZSIsInBhdGgiLCJqb2luIiwiX19kaXJuYW1lIiwiZml0IiwidGV4dCIsImFsaWdubWVudCIsIndpZHRoIiwiY29udGVudCIsImZvb3RlciIsImN1cnJlbnRQYWdlIiwicGFnZUNvdW50IiwidG9TdHJpbmciLCJwYWdlQnJlYWtCZWZvcmUiLCJjdXJyZW50Tm9kZSIsImZvbGxvd2luZ05vZGVzT25QYWdlIiwiaWQiLCJpbmNsdWRlcyIsImxlbmd0aCIsImZvbnRzIiwiUm9ib3RvIiwibm9ybWFsIiwiYm9sZCIsIml0YWxpY3MiLCJib2xkaXRhbGljcyIsIlJlcG9ydFByaW50ZXIiLCJjb25zdHJ1Y3RvciIsIl9wcmludGVyIiwiUGRmUHJpbnRlciIsIl9jb250ZW50IiwiYWRkQ29udGVudCIsInB1c2giLCJhZGRDb25maWdUYWJsZXMiLCJ0YWJsZXMiLCJ0YWJsZSIsInJvd3NwYXJzZWQiLCJyb3dzIiwiQXJyYXkiLCJpc0FycmF5Iiwic2xpY2UiLCJ0aXRsZSIsInN0eWxlIiwidHlwZSIsImZ1bGxfYm9keSIsIm1vZGlmaWVkUm93cyIsIm1hcCIsInJvdyIsImNlbGwiLCJ3aWR0aHMiLCJmaWxsIiwiY29sIiwiYm9yZGVyIiwiY29sU3BhbiIsImhlYWRlclJvd3MiLCJib2R5IiwiZG9udEJyZWFrUm93cyIsImxheW91dCIsImZpbGxDb2xvciIsImkiLCJoTGluZUNvbG9yIiwiaExpbmVXaWR0aCIsInZMaW5lV2lkdGgiLCJhZGROZXdMaW5lIiwiYWRkVGFibGVzIiwicGFnZUJyZWFrIiwicGFnZU9yaWVudGF0aW9uIiwic29ydFRhYmxlUm93cyIsImEiLCJiIiwicGFyc2VJbnQiLCJUaW1Tb3J0Iiwic29ydCIsImFkZFRpbWVSYW5nZUFuZEZpbHRlcnMiLCJmcm9tIiwidG8iLCJmaWx0ZXJzIiwidGltZVpvbmUiLCJmcm9tRGF0ZSIsIkRhdGUiLCJ0b0xvY2FsZVN0cmluZyIsInRvRGF0ZSIsInN0ciIsImZvcm1hdERhdGUiLCJzdmciLCJjbG9ja0ljb25SYXciLCJoZWlnaHQiLCJmaWx0ZXJJY29uUmF3IiwiYWRkVmlzdWFsaXphdGlvbnMiLCJ2aXN1YWxpemF0aW9ucyIsImlzQWdlbnRzIiwidGFiIiwic2luZ2xlX3ZpcyIsImZpbHRlciIsIml0ZW0iLCJkb3VibGVfdmlzIiwiZm9yRWFjaCIsInZpc3VhbGl6YXRpb24iLCJjaGVja1RpdGxlIiwiX3NvdXJjZSIsImVsZW1lbnQiLCJwYWlyIiwidGl0bGVfMSIsInRpdGxlXzIiLCJkYXRlIiwieWVhciIsImdldEZ1bGxZZWFyIiwibW9udGgiLCJnZXRNb250aCIsImRheSIsImdldERhdGUiLCJob3VycyIsImdldEhvdXJzIiwibWludXRlcyIsImdldE1pbnV0ZXMiLCJzZWNvbmRzIiwiZ2V0U2Vjb25kcyIsIkFnZW50c1Zpc3VhbGl6YXRpb25zIiwidiIsIl9pZCIsIk92ZXJ2aWV3VmlzdWFsaXphdGlvbnMiLCJhZGRTaW1wbGVUYWJsZSIsIml0ZW1zIiwidGFibGVIZWFkZXIiLCJjb2x1bW4iLCJsYWJlbCIsInRhYmxlUm93cyIsImluZGV4IiwiY2VsbFZhbHVlIiwidG90YWxMZW5ndGgiLCJ3aWR0aENvbHVtbiIsInRvdGFsV2lkdGgiLCJzdGVwIiwiY29sdW1uTGVuZ3RoIiwiZ2V0Q29sdW1uV2lkdGgiLCJNYXRoIiwicm91bmQiLCJhZGRMaXN0IiwibGlzdCIsImFkZENvbnRlbnRXaXRoTmV3TGluZSIsInVsIiwiYWRkQWdlbnRzRmlsdGVycyIsImFnZW50cyIsInByaW50IiwicmVwb3J0UGF0aCIsIlByb21pc2UiLCJyZXNvbHZlIiwicmVqZWN0IiwiY29uZmlndXJhdGlvbiIsImRvY3VtZW50IiwiY3JlYXRlUGRmS2l0RG9jdW1lbnQiLCJvbiIsInBpcGUiLCJmcyIsImNyZWF0ZVdyaXRlU3RyZWFtIiwiZW5kIiwiZXgiLCJ3aWR0aENoYXJhY3RlciIsIm1heFJvd0xlbmd0aCIsInJlZHVjZSIsIm1heExlbmd0aCIsImhlYWRlckxlbmd0aCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7QUFBQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFJQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7Ozs7O0FBRUEsTUFBTUEsTUFBTSxHQUFHO0FBQ2JDLEVBQUFBLE9BQU8sRUFBRUM7QUFESSxDQUFmOztBQUlBLE1BQU1DLGlCQUFpQixHQUFHLENBQUM7QUFBRUMsRUFBQUEsVUFBRjtBQUFjQyxFQUFBQSxVQUFkO0FBQTBCQyxFQUFBQTtBQUExQixDQUFELE1BQTZDO0FBQ3JFQyxFQUFBQSxNQUFNLEVBQUU7QUFDTkMsSUFBQUEsRUFBRSxFQUFFO0FBQ0ZDLE1BQUFBLFFBQVEsRUFBRSxFQURSO0FBRUZDLE1BQUFBLFNBQVMsRUFBRSxJQUZUO0FBR0ZDLE1BQUFBLEtBQUssRUFBRVgsTUFBTSxDQUFDQztBQUhaLEtBREU7QUFNTlcsSUFBQUEsRUFBRSxFQUFFO0FBQ0ZILE1BQUFBLFFBQVEsRUFBRSxFQURSO0FBRUZDLE1BQUFBLFNBQVMsRUFBRSxJQUZUO0FBR0ZDLE1BQUFBLEtBQUssRUFBRVgsTUFBTSxDQUFDQztBQUhaLEtBTkU7QUFXTlksSUFBQUEsRUFBRSxFQUFFO0FBQ0ZKLE1BQUFBLFFBQVEsRUFBRSxFQURSO0FBRUZDLE1BQUFBLFNBQVMsRUFBRSxJQUZUO0FBR0ZDLE1BQUFBLEtBQUssRUFBRVgsTUFBTSxDQUFDQztBQUhaLEtBWEU7QUFnQk5hLElBQUFBLEVBQUUsRUFBRTtBQUNGTCxN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LFVBQU04QixjQUFjLEdBQUcsQ0FBdkIsQ0FEc0MsQ0FDWjtBQUUxQjs7QUFDQSxVQUFNQyxZQUFZLEdBQUdoQyxTQUFTLENBQUNpQyxNQUFWLENBQWlCLENBQUNDLFNBQUQsRUFBWWpILEdBQVosS0FBa0I7QUFDdEQsYUFBUUEsR0FBRyxDQUFDZ0YsS0FBRCxDQUFILENBQVd6SCxJQUFYLENBQWdCYSxNQUFoQixHQUF5QjZJLFNBQXpCLEdBQXFDakgsR0FBRyxDQUFDZ0YsS0FBRCxDQUFILENBQVd6SCxJQUFYLENBQWdCYSxNQUFyRCxHQUE4RDZJLFNBQXRFO0FBQ0QsS0FGb0IsRUFFbkIsQ0FGbUIsQ0FBckIsQ0FKc0MsQ0FRdEM7O0FBQ0EsVUFBTUMsWUFBWSxHQUFHckMsTUFBTSxDQUFDQyxLQUFQLENBQWExRyxNQUFsQyxDQVRzQyxDQVd0Qzs7QUFDQSxVQUFNNkksU0FBUyxHQUFHRixZQUFZLEdBQUdHLFlBQWYsR0FBOEJILFlBQTlCLEdBQTZDRyxZQUEvRDtBQUVBLFdBQU9ELFNBQVMsR0FBR0gsY0FBbkI7QUFDRDs7QUF2aEJ1QiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBmcyBmcm9tICdmcyc7XG5pbXBvcnQgcGF0aCBmcm9tICdwYXRoJztcbmltcG9ydCBQZGZQcmludGVyIGZyb20gJ3BkZm1ha2Uvc3JjL3ByaW50ZXInO1xuaW1wb3J0IGNsb2NrSWNvblJhdyBmcm9tICcuL2Nsb2NrLWljb24tcmF3JztcbmltcG9ydCBmaWx0ZXJJY29uUmF3IGZyb20gJy4vZmlsdGVyLWljb24tcmF3JztcbmltcG9ydCB7XG4gIEFnZW50c1Zpc3VhbGl6YXRpb25zLFxuICBPdmVydmlld1Zpc3VhbGl6YXRpb25zXG59IGZyb20gJy4uLy4uL2ludGVncmF0aW9uLWZpbGVzL3Zpc3VhbGl6YXRpb25zJztcbmltcG9ydCB7IGxvZyB9IGZyb20gJy4uL2xvZ2dlcic7XG5pbXBvcnQgKiBhcyBUaW1Tb3J0IGZyb20gJ3RpbXNvcnQnO1xuaW1wb3J0IHsgZ2V0Q29uZmlndXJhdGlvbiB9IGZyb20gJy4uL2dldC1jb25maWd1cmF0aW9uJztcbmltcG9ydCB7IFJFUE9SVFNfUFJJTUFSWV9DT0xPUn0gZnJvbSAnLi4vLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgeyBnZXRDdXN0b21pemF0aW9uU2V0dGluZyB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9zZXJ2aWNlcy9zZXR0aW5ncyc7XG5cbmNvbnN0IENPTE9SUyA9IHtcbiAgUFJJTUFSWTogUkVQT1JUU19QUklNQVJZX0NPTE9SXG59O1xuXG5jb25zdCBwYWdlQ29uZmlndXJhdGlvbiA9ICh7IHBhdGhUb0xvZ28sIHBhZ2VIZWFkZXIsIHBhZ2VGb290ZXIgfSkgPT4gKHtcbiAgc3R5bGVzOiB7XG4gICAgaDE6IHtcbiAgICAgIGZvbnRTaXplOiAyMixcbiAgICAgIG1vbnNsaWdodDogdHJ1ZSxcbiAgICAgIGNvbG9yOiBDT0xPUlMuUFJJTUFSWVxuICAgIH0sXG4gICAgaDI6IHtcbiAgICAgIGZvbnRTaXplOiAxOCxcbiAgICAgIG1vbnNsaWdodDogdHJ1ZSxcbiAgICAgIGNvbG9yOiBDT0xPUlMuUFJJTUFSWVxuICAgIH0sXG4gICAgaDM6IHtcbiAgICAgIGZvbnRTaXplOiAxNixcbiAgICAgIG1vbnNsaWdodDogdHJ1ZSxcbiAgICAgIGNvbG9yOiBDT0xPUlMuUFJJTUFSWVxuICAgIH0sXG4gICAgaDQ6IHtcbiAgICAgIGZvbnRTaXplOiAxNCxcbiAgICAgIG1vbnNsaWdodDogdHJ1ZSxcbiAgICAgIGNvbG9yOiBDT0xPUlMuUFJJTUFSWVxuICAgIH0sXG4gICAgc3RhbmRhcmQ6IHtcbiAgICAgIGNvbG9yOiAnIzMzMydcbiAgICB9LFxuICAgIHdoaXRlQ29sb3JGaWx0ZXJzOiB7XG4gICAgICBjb2xvcjogJyNGRkYnLFxuICAgICAgZm9udFNpemU6IDE0XG4gICAgfSxcbiAgICB3aGl0ZUNvbG9yOiB7XG4gICAgICBjb2xvcjogJyNGRkYnXG4gICAgfVxuICB9LFxuICBwYWdlTWFyZ2luczogWzQwLCA4MCwgNDAsIDgwXSxcbiAgaGVhZGVyOiB7XG4gICAgbWFyZ2luOiBbNDAsIDIwLCAwLCAwXSxcbiAgICBjb2x1bW5zOiBbXG4gICAgICB7XG4gICAgICAgIGltYWdlOiBwYXRoLmpvaW4oX19kaXJuYW1lLCBgLi4vLi4vLi4vcHVibGljL2Fzc2V0cy8ke3BhdGhUb0xvZ299YCksXG4gICAgICAgIGZpdDogWzE5MCwgNTBdXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICB0ZXh0OiBwYWdlSGVhZGVyLFxuICAgICAgICBhbGlnbm1lbnQ6ICdyaWdodCcsXG4gICAgICAgIG1hcmdpbjogWzAsIDAsIDQwLCAwXSxcbiAgICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZLFxuICAgICAgICB3aWR0aDogJ2F1dG8nXG4gICAgICB9XG4gICAgXVxuICB9LFxuICBjb250ZW50OiBbXSxcbiAgZm9vdGVyKGN1cnJlbnRQYWdlLCBwYWdlQ291bnQpIHtcbiAgICByZXR1cm4ge1xuICAgICAgY29sdW1uczogW1xuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogcGFnZUZvb3RlcixcbiAgICAgICAgICBjb2xvcjogQ09MT1JTLlBSSU1BUlksXG4gICAgICAgICAgbWFyZ2luOiBbNDAsIDQwLCAwLCAwXVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogJ1BhZ2UgJyArIGN1cnJlbnRQYWdlLnRvU3RyaW5nKCkgKyAnIG9mICcgKyBwYWdlQ291bnQsXG4gICAgICAgICAgYWxpZ25tZW50OiAncmlnaHQnLFxuICAgICAgICAgIG1hcmdpbjogWzAsIDQwLCA0MCwgMF0sXG4gICAgICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZLFxuICAgICAgICAgIHdpZHRoOiAnYXV0bydcbiAgICAgICAgfVxuICAgICAgXVxuICAgIH07XG4gIH0sXG4gIHBhZ2VCcmVha0JlZm9yZShjdXJyZW50Tm9kZSwgZm9sbG93aW5nTm9kZXNPblBhZ2UpIHtcbiAgICBpZiAoY3VycmVudE5vZGUuaWQgJiYgY3VycmVudE5vZGUuaWQuaW5jbHVkZXMoJ3NwbGl0dmlzJykpIHtcbiAgICAgIHJldHVybiAoXG4gICAgICAgIGZvbGxvd2luZ05vZGVzT25QYWdlLmxlbmd0aCA9PT0gNiB8fFxuICAgICAgICBmb2xsb3dpbmdOb2Rlc09uUGFnZS5sZW5ndGggPT09IDdcbiAgICAgICk7XG4gICAgfVxuICAgIGlmIChcbiAgICAgIChjdXJyZW50Tm9kZS5pZCAmJiBjdXJyZW50Tm9kZS5pZC5pbmNsdWRlcygnc3BsaXRzaW5nbGV2aXMnKSkgfHxcbiAgICAgIChjdXJyZW50Tm9kZS5pZCAmJiBjdXJyZW50Tm9kZS5pZC5pbmNsdWRlcygnc2luZ2xldmlzJykpXG4gICAgKSB7XG4gICAgICByZXR1cm4gZm9sbG93aW5nTm9kZXNPblBhZ2UubGVuZ3RoID09PSA2O1xuICAgIH1cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbn0pO1xuXG5jb25zdCBmb250cyA9IHtcbiAgUm9ib3RvOiB7XG4gICAgbm9ybWFsOiBwYXRoLmpvaW4oXG4gICAgICBfX2Rpcm5hbWUsXG4gICAgICAnLi4vLi4vLi4vcHVibGljL2Fzc2V0cy9mb250cy9vcGVuc2Fucy9PcGVuU2Fucy1MaWdodC50dGYnXG4gICAgKSxcbiAgICBib2xkOiBwYXRoLmpvaW4oXG4gICAgICBfX2Rpcm5hbWUsXG4gICAgICAnLi4vLi4vLi4vcHVibGljL2Fzc2V0cy9mb250cy9vcGVuc2Fucy9PcGVuU2Fucy1Cb2xkLnR0ZidcbiAgICApLFxuICAgIGl0YWxpY3M6IHBhdGguam9pbihcbiAgICAgIF9fZGlybmFtZSxcbiAgICAgICcuLi8uLi8uLi9wdWJsaWMvYXNzZXRzL2ZvbnRzL29wZW5zYW5zL09wZW5TYW5zLUl0YWxpYy50dGYnXG4gICAgKSxcbiAgICBib2xkaXRhbGljczogcGF0aC5qb2luKFxuICAgICAgX19kaXJuYW1lLFxuICAgICAgJy4uLy4uLy4uL3B1YmxpYy9hc3NldHMvZm9udHMvb3BlbnNhbnMvT3BlblNhbnMtQm9sZEl0YWxpYy50dGYnXG4gICAgKSxcbiAgICBtb25zbGlnaHQ6IHBhdGguam9pbihcbiAgICAgIF9fZGlybmFtZSxcbiAgICAgICcuLi8uLi8uLi9wdWJsaWMvYXNzZXRzL2ZvbnRzL29wZW5zYW5zL01vbnRzZXJyYXQtTGlnaHQudHRmJ1xuICAgIClcbiAgfVxufTtcblxuZXhwb3J0IGNsYXNzIFJlcG9ydFByaW50ZXJ7XG4gIHByaXZhdGUgX2NvbnRlbnQ6IGFueVtdO1xuICBwcml2YXRlIF9wcmludGVyOiBQZGZQcmludGVyO1xuICBjb25zdHJ1Y3Rvcigpe1xuICAgIHRoaXMuX3ByaW50ZXIgPSBuZXcgUGRmUHJpbnRlcihmb250cyk7XG4gICAgdGhpcy5fY29udGVudCA9IFtdO1xuICB9XG4gIGFkZENvbnRlbnQoLi4uY29udGVudDogYW55KXtcbiAgICB0aGlzLl9jb250ZW50LnB1c2goLi4uY29udGVudCk7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cbiAgYWRkQ29uZmlnVGFibGVzKHRhYmxlczogYW55KXtcbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOnJlbmRlckNvbmZpZ1RhYmxlcycsXG4gICAgICAnU3RhcnRlZCB0byByZW5kZXIgY29uZmlndXJhdGlvbiB0YWJsZXMnLFxuICAgICAgJ2luZm8nXG4gICAgKTtcbiAgICBsb2coJ3JlcG9ydGluZzpyZW5kZXJDb25maWdUYWJsZXMnLCBgdGFibGVzOiAke3RhYmxlcy5sZW5ndGh9YCwgJ2RlYnVnJyk7XG4gICAgZm9yIChjb25zdCB0YWJsZSBvZiB0YWJsZXMpIHtcbiAgICAgIGxldCByb3dzcGFyc2VkID0gdGFibGUucm93cztcbiAgICAgIGlmIChBcnJheS5pc0FycmF5KHJvd3NwYXJzZWQpICYmIHJvd3NwYXJzZWQubGVuZ3RoKSB7XG4gICAgICAgIGNvbnN0IHJvd3MgPVxuICAgICAgICAgIHJvd3NwYXJzZWQubGVuZ3RoID4gMTAwID8gcm93c3BhcnNlZC5zbGljZSgwLCA5OSkgOiByb3dzcGFyc2VkO1xuICAgICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICAgIHRleHQ6IHRhYmxlLnRpdGxlLFxuICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAxMSwgY29sb3I6ICcjMDAwJyB9LFxuICAgICAgICAgIG1hcmdpbjogdGFibGUudGl0bGUgJiYgdGFibGUudHlwZSA9PT0gJ3RhYmxlJyA/IFswLCAwLCAwLCA1XSA6ICcnXG4gICAgICAgIH0pO1xuXG4gICAgICAgIGlmICh0YWJsZS50aXRsZSA9PT0gJ01vbml0b3JlZCBkaXJlY3RvcmllcycpIHtcbiAgICAgICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgdGV4dDpcbiAgICAgICAgICAgICAgJ1JUOiBSZWFsIHRpbWUgfCBXRDogV2hvLWRhdGEgfCBQZXIuOiBQZXJtaXNzaW9uIHwgTVQ6IE1vZGlmaWNhdGlvbiB0aW1lIHwgU0w6IFN5bWJvbGljIGxpbmsgfCBSTDogUmVjdXJzaW9uIGxldmVsJyxcbiAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiA4LCBjb2xvcjogQ09MT1JTLlBSSU1BUlkgfSxcbiAgICAgICAgICAgIG1hcmdpbjogWzAsIDAsIDAsIDVdXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBmdWxsX2JvZHkgPSBbXTtcblxuICAgICAgICBjb25zdCBtb2RpZmllZFJvd3MgPSByb3dzLm1hcChyb3cgPT4gcm93Lm1hcChjZWxsID0+ICh7IHRleHQ6IGNlbGwgfHwgJy0nLCBzdHlsZTogJ3N0YW5kYXJkJyB9KSkpO1xuICAgICAgICAvLyBmb3IgKGNvbnN0IHJvdyBvZiByb3dzKSB7XG4gICAgICAgIC8vICAgbW9kaWZpZWRSb3dzLnB1c2goXG4gICAgICAgIC8vICAgICByb3cubWFwKGNlbGwgPT4gKHsgdGV4dDogY2VsbCB8fCAnLScsIHN0eWxlOiAnc3RhbmRhcmQnIH0pKVxuICAgICAgICAvLyAgICk7XG4gICAgICAgIC8vIH1cbiAgICAgICAgbGV0IHdpZHRocyA9IFtdO1xuICAgICAgICB3aWR0aHMgPSBBcnJheSh0YWJsZS5jb2x1bW5zLmxlbmd0aCAtIDEpLmZpbGwoJ2F1dG8nKTtcbiAgICAgICAgd2lkdGhzLnB1c2goJyonKTtcblxuICAgICAgICBpZiAodGFibGUudHlwZSA9PT0gJ2NvbmZpZycpIHtcbiAgICAgICAgICBmdWxsX2JvZHkucHVzaChcbiAgICAgICAgICAgIHRhYmxlLmNvbHVtbnMubWFwKGNvbCA9PiAoe1xuICAgICAgICAgICAgICB0ZXh0OiBjb2wgfHwgJy0nLFxuICAgICAgICAgICAgICBib3JkZXI6IFswLCAwLCAwLCAyMF0sXG4gICAgICAgICAgICAgIGZvbnRTaXplOiAwLFxuICAgICAgICAgICAgICBjb2xTcGFuOiAyXG4gICAgICAgICAgICB9KSksXG4gICAgICAgICAgICAuLi5tb2RpZmllZFJvd3NcbiAgICAgICAgICApO1xuICAgICAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgICAgICBmb250U2l6ZTogOCxcbiAgICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICAgIGhlYWRlclJvd3M6IDAsXG4gICAgICAgICAgICAgIHdpZHRocyxcbiAgICAgICAgICAgICAgYm9keTogZnVsbF9ib2R5LFxuICAgICAgICAgICAgICBkb250QnJlYWtSb3dzOiB0cnVlXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgbGF5b3V0OiB7XG4gICAgICAgICAgICAgIGZpbGxDb2xvcjogaSA9PiAoaSA9PT0gMCA/ICcjZmZmJyA6IG51bGwpLFxuICAgICAgICAgICAgICBoTGluZUNvbG9yOiAoKSA9PiAnI0QzREFFNicsXG4gICAgICAgICAgICAgIGhMaW5lV2lkdGg6ICgpID0+IDEsXG4gICAgICAgICAgICAgIHZMaW5lV2lkdGg6ICgpID0+IDBcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIGlmICh0YWJsZS50eXBlID09PSAndGFibGUnKSB7XG4gICAgICAgICAgZnVsbF9ib2R5LnB1c2goXG4gICAgICAgICAgICB0YWJsZS5jb2x1bW5zLm1hcChjb2wgPT4gKHtcbiAgICAgICAgICAgICAgdGV4dDogY29sIHx8ICctJyxcbiAgICAgICAgICAgICAgc3R5bGU6ICd3aGl0ZUNvbG9yJyxcbiAgICAgICAgICAgICAgYm9yZGVyOiBbMCwgMCwgMCwgMF1cbiAgICAgICAgICAgIH0pKSxcbiAgICAgICAgICAgIC4uLm1vZGlmaWVkUm93c1xuICAgICAgICAgICk7XG4gICAgICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIGZvbnRTaXplOiA4LFxuICAgICAgICAgICAgdGFibGU6IHtcbiAgICAgICAgICAgICAgaGVhZGVyUm93czogMSxcbiAgICAgICAgICAgICAgd2lkdGhzLFxuICAgICAgICAgICAgICBib2R5OiBmdWxsX2JvZHlcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBsYXlvdXQ6IHtcbiAgICAgICAgICAgICAgZmlsbENvbG9yOiBpID0+IChpID09PSAwID8gQ09MT1JTLlBSSU1BUlkgOiBudWxsKSxcbiAgICAgICAgICAgICAgaExpbmVDb2xvcjogKCkgPT4gQ09MT1JTLlBSSU1BUlksXG4gICAgICAgICAgICAgIGhMaW5lV2lkdGg6ICgpID0+IDEsXG4gICAgICAgICAgICAgIHZMaW5lV2lkdGg6ICgpID0+IDBcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLmFkZE5ld0xpbmUoKTtcbiAgICAgIH1cbiAgICAgIGxvZygncmVwb3J0aW5nOnJlbmRlckNvbmZpZ1RhYmxlcycsIGBUYWJsZSByZW5kZXJlZGAsICdkZWJ1ZycpO1xuICAgIH1cbiAgfVxuXG4gIGFkZFRhYmxlcyh0YWJsZXM6IGFueSl7XG4gICAgbG9nKCdyZXBvcnRpbmc6cmVuZGVyVGFibGVzJywgJ1N0YXJ0ZWQgdG8gcmVuZGVyIHRhYmxlcycsICdpbmZvJyk7XG4gICAgbG9nKCdyZXBvcnRpbmc6cmVuZGVyVGFibGVzJywgYHRhYmxlczogJHt0YWJsZXMubGVuZ3RofWAsICdkZWJ1ZycpO1xuICAgIGZvciAoY29uc3QgdGFibGUgb2YgdGFibGVzKSB7XG4gICAgICBsZXQgcm93c3BhcnNlZCA9IFtdO1xuICAgICAgcm93c3BhcnNlZCA9IHRhYmxlLnJvd3M7XG4gICAgICBpZiAoQXJyYXkuaXNBcnJheShyb3dzcGFyc2VkKSAmJiByb3dzcGFyc2VkLmxlbmd0aCkge1xuICAgICAgICBjb25zdCByb3dzID1cbiAgICAgICAgICByb3dzcGFyc2VkLmxlbmd0aCA+IDEwMCA/IHJvd3NwYXJzZWQuc2xpY2UoMCwgOTkpIDogcm93c3BhcnNlZDtcbiAgICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgICB0ZXh0OiB0YWJsZS50aXRsZSxcbiAgICAgICAgICBzdHlsZTogJ2gzJyxcbiAgICAgICAgICBwYWdlQnJlYWs6ICdiZWZvcmUnLFxuICAgICAgICAgIHBhZ2VPcmllbnRhdGlvbjogdGFibGUuY29sdW1ucy5sZW5ndGggPj0gOSA/ICdsYW5kc2NhcGUnIDogJ3BvcnRyYWl0JyxcbiAgICAgICAgfSk7XG4gICAgICAgIHRoaXMuYWRkTmV3TGluZSgpO1xuICAgICAgICBjb25zdCBmdWxsX2JvZHkgPSBbXTtcbiAgICAgICAgY29uc3Qgc29ydFRhYmxlUm93cyA9IChhLCBiKSA9PlxuICAgICAgICAgIHBhcnNlSW50KGFbYS5sZW5ndGggLSAxXSkgPCBwYXJzZUludChiW2IubGVuZ3RoIC0gMV0pXG4gICAgICAgICAgICA/IDFcbiAgICAgICAgICAgIDogcGFyc2VJbnQoYVthLmxlbmd0aCAtIDFdKSA+IHBhcnNlSW50KGJbYi5sZW5ndGggLSAxXSlcbiAgICAgICAgICAgID8gLTFcbiAgICAgICAgICAgIDogMDtcblxuICAgICAgICBUaW1Tb3J0LnNvcnQocm93cywgc29ydFRhYmxlUm93cyk7XG5cbiAgICAgICAgY29uc3QgbW9kaWZpZWRSb3dzID0gcm93cy5tYXAocm93ID0+IHJvdy5tYXAoY2VsbCA9PiAoeyB0ZXh0OiBjZWxsIHx8ICctJywgc3R5bGU6ICdzdGFuZGFyZCcgfSkpKTtcblxuICAgICAgICAvLyB0aGUgd2lkdGggb2YgdGhlIGNvbHVtbnMgaXMgYXNzaWduZWRcbiAgICAgICAgY29uc3Qgd2lkdGhzID0gQXJyYXkodGFibGUuY29sdW1ucy5sZW5ndGggLSAxKS5maWxsKCdhdXRvJyk7XG4gICAgICAgIHdpZHRocy5wdXNoKCcqJyk7XG5cbiAgICAgICAgZnVsbF9ib2R5LnB1c2goXG4gICAgICAgICAgdGFibGUuY29sdW1ucy5tYXAoY29sID0+ICh7XG4gICAgICAgICAgICB0ZXh0OiBjb2wgfHwgJy0nLFxuICAgICAgICAgICAgc3R5bGU6ICd3aGl0ZUNvbG9yJyxcbiAgICAgICAgICAgIGJvcmRlcjogWzAsIDAsIDAsIDBdXG4gICAgICAgICAgfSkpLFxuICAgICAgICAgIC4uLm1vZGlmaWVkUm93c1xuICAgICAgICApO1xuICAgICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICAgIGZvbnRTaXplOiA4LFxuICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICBoZWFkZXJSb3dzOiAxLFxuICAgICAgICAgICAgd2lkdGhzLFxuICAgICAgICAgICAgYm9keTogZnVsbF9ib2R5XG4gICAgICAgICAgfSxcbiAgICAgICAgICBsYXlvdXQ6IHtcbiAgICAgICAgICAgIGZpbGxDb2xvcjogaSA9PiAoaSA9PT0gMCA/IENPTE9SUy5QUklNQVJZIDogbnVsbCksXG4gICAgICAgICAgICBoTGluZUNvbG9yOiAoKSA9PiBDT0xPUlMuUFJJTUFSWSxcbiAgICAgICAgICAgIGhMaW5lV2lkdGg6ICgpID0+IDEsXG4gICAgICAgICAgICB2TGluZVdpZHRoOiAoKSA9PiAwXG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgdGhpcy5hZGROZXdMaW5lKCk7XG4gICAgICAgIGxvZygncmVwb3J0aW5nOnJlbmRlclRhYmxlcycsIGBUYWJsZSByZW5kZXJlZGAsICdkZWJ1ZycpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuICBhZGRUaW1lUmFuZ2VBbmRGaWx0ZXJzKGZyb20sIHRvLCBmaWx0ZXJzLCB0aW1lWm9uZSl7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzpyZW5kZXJUaW1lUmFuZ2VBbmRGaWx0ZXJzJyxcbiAgICAgIGBTdGFydGVkIHRvIHJlbmRlciB0aGUgdGltZSByYW5nZSBhbmQgdGhlIGZpbHRlcnNgLFxuICAgICAgJ2luZm8nXG4gICAgKTtcbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOnJlbmRlclRpbWVSYW5nZUFuZEZpbHRlcnMnLFxuICAgICAgYGZyb206ICR7ZnJvbX0sIHRvOiAke3RvfSwgZmlsdGVyczogJHtmaWx0ZXJzfSwgdGltZVpvbmU6ICR7dGltZVpvbmV9YCxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICAgIGNvbnN0IGZyb21EYXRlID0gbmV3IERhdGUoXG4gICAgICBuZXcgRGF0ZShmcm9tKS50b0xvY2FsZVN0cmluZygnZW4tVVMnLCB7IHRpbWVab25lIH0pXG4gICAgKTtcbiAgICBjb25zdCB0b0RhdGUgPSBuZXcgRGF0ZShuZXcgRGF0ZSh0bykudG9Mb2NhbGVTdHJpbmcoJ2VuLVVTJywgeyB0aW1lWm9uZSB9KSk7XG4gICAgY29uc3Qgc3RyID0gYCR7dGhpcy5mb3JtYXREYXRlKGZyb21EYXRlKX0gdG8gJHt0aGlzLmZvcm1hdERhdGUodG9EYXRlKX1gO1xuXG4gICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgIGZvbnRTaXplOiA4LFxuICAgICAgdGFibGU6IHtcbiAgICAgICAgd2lkdGhzOiBbJyonXSxcbiAgICAgICAgYm9keTogW1xuICAgICAgICAgIFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgIHN2ZzogY2xvY2tJY29uUmF3LFxuICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwLFxuICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAxMCxcbiAgICAgICAgICAgICAgICAgIG1hcmdpbjogWzQwLCA1LCAwLCAwXVxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgdGV4dDogc3RyIHx8ICctJyxcbiAgICAgICAgICAgICAgICAgIG1hcmdpbjogWzQzLCAwLCAwLCAwXSxcbiAgICAgICAgICAgICAgICAgIHN0eWxlOiAnd2hpdGVDb2xvckZpbHRlcnMnXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBdXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXSxcbiAgICAgICAgICBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICBzdmc6IGZpbHRlckljb25SYXcsXG4gICAgICAgICAgICAgICAgICB3aWR0aDogMTAsXG4gICAgICAgICAgICAgICAgICBoZWlnaHQ6IDEwLFxuICAgICAgICAgICAgICAgICAgbWFyZ2luOiBbNDAsIDYsIDAsIDBdXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICB0ZXh0OiBmaWx0ZXJzIHx8ICctJyxcbiAgICAgICAgICAgICAgICAgIG1hcmdpbjogWzQzLCAwLCAwLCAwXSxcbiAgICAgICAgICAgICAgICAgIHN0eWxlOiAnd2hpdGVDb2xvckZpbHRlcnMnXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBdXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICBdXG4gICAgICB9LFxuICAgICAgbWFyZ2luOiBbLTQwLCAwLCAtNDAsIDBdLFxuICAgICAgbGF5b3V0OiB7XG4gICAgICAgIGZpbGxDb2xvcjogKCkgPT4gQ09MT1JTLlBSSU1BUlksXG4gICAgICAgIGhMaW5lV2lkdGg6ICgpID0+IDAsXG4gICAgICAgIHZMaW5lV2lkdGg6ICgpID0+IDBcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIHRoaXMuYWRkQ29udGVudCh7IHRleHQ6ICdcXG4nIH0pO1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6cmVuZGVyVGltZVJhbmdlQW5kRmlsdGVycycsXG4gICAgICAnVGltZSByYW5nZSBhbmQgZmlsdGVycyByZW5kZXJlZCcsXG4gICAgICAnZGVidWcnXG4gICAgKTtcbiAgfVxuICBhZGRWaXN1YWxpemF0aW9ucyh2aXN1YWxpemF0aW9ucywgaXNBZ2VudHMsIHRhYil7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzpyZW5kZXJWaXN1YWxpemF0aW9ucycsXG4gICAgICBgJHt2aXN1YWxpemF0aW9ucy5sZW5ndGh9IHZpc3VhbGl6YXRpb25zIGZvciB0YWIgJHt0YWJ9YCxcbiAgICAgICdpbmZvJ1xuICAgICk7XG4gICAgY29uc3Qgc2luZ2xlX3ZpcyA9IHZpc3VhbGl6YXRpb25zLmZpbHRlcihpdGVtID0+IGl0ZW0ud2lkdGggPj0gNjAwKTtcbiAgICBjb25zdCBkb3VibGVfdmlzID0gdmlzdWFsaXphdGlvbnMuZmlsdGVyKGl0ZW0gPT4gaXRlbS53aWR0aCA8IDYwMCk7XG5cbiAgICBzaW5nbGVfdmlzLmZvckVhY2godmlzdWFsaXphdGlvbiA9PiB7XG4gICAgICBjb25zdCB0aXRsZSA9IHRoaXMuY2hlY2tUaXRsZSh2aXN1YWxpemF0aW9uLCBpc0FnZW50cywgdGFiKTtcbiAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgIGlkOiAnc2luZ2xldmlzJyArIHRpdGxlWzBdLl9zb3VyY2UudGl0bGUsXG4gICAgICAgIHRleHQ6IHRpdGxlWzBdLl9zb3VyY2UudGl0bGUsXG4gICAgICAgIHN0eWxlOiAnaDMnXG4gICAgICB9KTtcbiAgICAgIHRoaXMuYWRkQ29udGVudCh7IGNvbHVtbnM6IFt7IGltYWdlOiB2aXN1YWxpemF0aW9uLmVsZW1lbnQsIHdpZHRoOiA1MDAgfV0gfSk7XG4gICAgICB0aGlzLmFkZE5ld0xpbmUoKTtcbiAgICB9KVxuXG4gICAgbGV0IHBhaXIgPSBbXTtcblxuICAgIGZvciAoY29uc3QgaXRlbSBvZiBkb3VibGVfdmlzKSB7XG4gICAgICBwYWlyLnB1c2goaXRlbSk7XG4gICAgICBpZiAocGFpci5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgY29uc3QgdGl0bGVfMSA9IHRoaXMuY2hlY2tUaXRsZShwYWlyWzBdLCBpc0FnZW50cywgdGFiKTtcbiAgICAgICAgY29uc3QgdGl0bGVfMiA9IHRoaXMuY2hlY2tUaXRsZShwYWlyWzFdLCBpc0FnZW50cywgdGFiKTtcblxuICAgICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdzcGxpdHZpcycgKyB0aXRsZV8xWzBdLl9zb3VyY2UudGl0bGUsXG4gICAgICAgICAgICAgIHRleHQ6IHRpdGxlXzFbMF0uX3NvdXJjZS50aXRsZSxcbiAgICAgICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgICAgIHdpZHRoOiAyODBcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnc3BsaXR2aXMnICsgdGl0bGVfMlswXS5fc291cmNlLnRpdGxlLFxuICAgICAgICAgICAgICB0ZXh0OiB0aXRsZV8yWzBdLl9zb3VyY2UudGl0bGUsXG4gICAgICAgICAgICAgIHN0eWxlOiAnaDMnLFxuICAgICAgICAgICAgICB3aWR0aDogMjgwXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgIHsgaW1hZ2U6IHBhaXJbMF0uZWxlbWVudCwgd2lkdGg6IDI3MCB9LFxuICAgICAgICAgICAgeyBpbWFnZTogcGFpclsxXS5lbGVtZW50LCB3aWR0aDogMjcwIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0pO1xuXG4gICAgICAgIHRoaXMuYWRkTmV3TGluZSgpO1xuICAgICAgICBwYWlyID0gW107XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGRvdWJsZV92aXMubGVuZ3RoICUgMiAhPT0gMCkge1xuICAgICAgY29uc3QgaXRlbSA9IGRvdWJsZV92aXNbZG91YmxlX3Zpcy5sZW5ndGggLSAxXTtcbiAgICAgIGNvbnN0IHRpdGxlID0gdGhpcy5jaGVja1RpdGxlKGl0ZW0sIGlzQWdlbnRzLCB0YWIpO1xuICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnc3BsaXRzaW5nbGV2aXMnICsgdGl0bGVbMF0uX3NvdXJjZS50aXRsZSxcbiAgICAgICAgICAgIHRleHQ6IHRpdGxlWzBdLl9zb3VyY2UudGl0bGUsXG4gICAgICAgICAgICBzdHlsZTogJ2gzJyxcbiAgICAgICAgICAgIHdpZHRoOiAyODBcbiAgICAgICAgICB9XG4gICAgICAgIF1cbiAgICAgIH0pO1xuICAgICAgdGhpcy5hZGRDb250ZW50KHsgY29sdW1uczogW3sgaW1hZ2U6IGl0ZW0uZWxlbWVudCwgd2lkdGg6IDI4MCB9XSB9KTtcbiAgICAgIHRoaXMuYWRkTmV3TGluZSgpO1xuICAgIH1cbiAgfVxuICBmb3JtYXREYXRlKGRhdGU6IERhdGUpOiBzdHJpbmcge1xuICAgIGxvZygncmVwb3J0aW5nOmZvcm1hdERhdGUnLCBgRm9ybWF0IGRhdGUgJHtkYXRlfWAsICdpbmZvJyk7XG4gICAgY29uc3QgeWVhciA9IGRhdGUuZ2V0RnVsbFllYXIoKTtcbiAgICBjb25zdCBtb250aCA9IGRhdGUuZ2V0TW9udGgoKSArIDE7XG4gICAgY29uc3QgZGF5ID0gZGF0ZS5nZXREYXRlKCk7XG4gICAgY29uc3QgaG91cnMgPSBkYXRlLmdldEhvdXJzKCk7XG4gICAgY29uc3QgbWludXRlcyA9IGRhdGUuZ2V0TWludXRlcygpO1xuICAgIGNvbnN0IHNlY29uZHMgPSBkYXRlLmdldFNlY29uZHMoKTtcbiAgICBjb25zdCBzdHIgPSBgJHt5ZWFyfS0ke21vbnRoIDwgMTAgPyAnMCcgKyBtb250aCA6IG1vbnRofS0ke1xuICAgICAgZGF5IDwgMTAgPyAnMCcgKyBkYXkgOiBkYXlcbiAgICB9VCR7aG91cnMgPCAxMCA/ICcwJyArIGhvdXJzIDogaG91cnN9OiR7XG4gICAgICBtaW51dGVzIDwgMTAgPyAnMCcgKyBtaW51dGVzIDogbWludXRlc1xuICAgIH06JHtzZWNvbmRzIDwgMTAgPyAnMCcgKyBzZWNvbmRzIDogc2Vjb25kc31gO1xuICAgIGxvZygncmVwb3J0aW5nOmZvcm1hdERhdGUnLCBgc3RyOiAke3N0cn1gLCAnZGVidWcnKTtcbiAgICByZXR1cm4gc3RyO1xuICB9XG4gIGNoZWNrVGl0bGUoaXRlbSwgaXNBZ2VudHMsIHRhYikge1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6Y2hlY2tUaXRsZScsXG4gICAgICBgSXRlbSBJRCAke2l0ZW0uaWR9LCBmcm9tICR7XG4gICAgICAgIGlzQWdlbnRzID8gJ2FnZW50cycgOiAnb3ZlcnZpZXcnXG4gICAgICB9IGFuZCB0YWIgJHt0YWJ9YCxcbiAgICAgICdpbmZvJ1xuICAgICk7XG5cbiAgICBjb25zdCB0aXRsZSA9IGlzQWdlbnRzXG4gICAgICA/IEFnZW50c1Zpc3VhbGl6YXRpb25zW3RhYl0uZmlsdGVyKHYgPT4gdi5faWQgPT09IGl0ZW0uaWQpXG4gICAgICA6IE92ZXJ2aWV3VmlzdWFsaXphdGlvbnNbdGFiXS5maWx0ZXIodiA9PiB2Ll9pZCA9PT0gaXRlbS5pZCk7XG4gICAgcmV0dXJuIHRpdGxlO1xuICB9XG5cbiAgYWRkU2ltcGxlVGFibGUoe2NvbHVtbnMsIGl0ZW1zLCB0aXRsZX06IHtjb2x1bW5zOiAoe2lkOiBzdHJpbmcsIGxhYmVsOiBzdHJpbmd9KVtdLCB0aXRsZT86IChzdHJpbmcgfCB7dGV4dDogc3RyaW5nLCBzdHlsZTogc3RyaW5nfSksIGl0ZW1zOiBhbnlbXX0pe1xuXG4gICAgaWYgKHRpdGxlKSB7XG4gICAgICB0aGlzLmFkZENvbnRlbnQodHlwZW9mIHRpdGxlID09PSAnc3RyaW5nJyA/IHsgdGV4dDogdGl0bGUsIHN0eWxlOiAnaDQnIH0gOiB0aXRsZSlcbiAgICAgICAgLmFkZE5ld0xpbmUoKTtcbiAgICB9XG5cbiAgICBpZiAoIWl0ZW1zIHx8ICFpdGVtcy5sZW5ndGgpIHtcbiAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgIHRleHQ6ICdObyByZXN1bHRzIG1hdGNoIHlvdXIgc2VhcmNoIGNyaXRlcmlhJyxcbiAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCdcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuXG4gICAgY29uc3QgdGFibGVIZWFkZXIgPSBjb2x1bW5zLm1hcChjb2x1bW4gPT4ge1xuICAgICAgcmV0dXJuIHsgdGV4dDogY29sdW1uLmxhYmVsLCBzdHlsZTogJ3doaXRlQ29sb3InLCBib3JkZXI6IFswLCAwLCAwLCAwXSB9O1xuICAgIH0pO1xuXG4gICAgY29uc3QgdGFibGVSb3dzID0gaXRlbXMubWFwKChpdGVtLCBpbmRleCkgPT4ge1xuICAgICAgcmV0dXJuIGNvbHVtbnMubWFwKGNvbHVtbiA9PiB7XG4gICAgICAgIGNvbnN0IGNlbGxWYWx1ZSA9IGl0ZW1bY29sdW1uLmlkXTtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICB0ZXh0OiB0eXBlb2YgY2VsbFZhbHVlICE9PSAndW5kZWZpbmVkJyA/IGNlbGxWYWx1ZSA6ICctJyxcbiAgICAgICAgICBzdHlsZTogJ3N0YW5kYXJkJ1xuICAgICAgICB9XG4gICAgICB9KVxuICAgIH0pO1xuXG4gICAgLy8gMzg1IGlzIHRoZSBtYXggaW5pdGlhbCB3aWR0aCBwZXIgY29sdW1uXG4gICAgbGV0IHRvdGFsTGVuZ3RoID0gY29sdW1ucy5sZW5ndGggLSAxO1xuICAgIGNvbnN0IHdpZHRoQ29sdW1uID0gMzg1L3RvdGFsTGVuZ3RoO1xuICAgIGxldCB0b3RhbFdpZHRoID0gdG90YWxMZW5ndGggKiB3aWR0aENvbHVtbjtcblxuICAgIGNvbnN0IHdpZHRoczoobnVtYmVyKVtdID0gW107XG5cbiAgICBmb3IgKGxldCBzdGVwID0gMDsgc3RlcCA8IGNvbHVtbnMubGVuZ3RoIC0gMTsgc3RlcCsrKSB7XG5cbiAgICAgIGxldCBjb2x1bW5MZW5ndGggPSB0aGlzLmdldENvbHVtbldpZHRoKGNvbHVtbnNbc3RlcF0sIHRhYmxlUm93cywgc3RlcCk7XG5cbiAgICAgIGlmIChjb2x1bW5MZW5ndGggPD0gTWF0aC5yb3VuZCh0b3RhbFdpZHRoIC8gdG90YWxMZW5ndGgpKSB7XG4gICAgICAgIHdpZHRocy5wdXNoKGNvbHVtbkxlbmd0aCk7XG4gICAgICAgIHRvdGFsV2lkdGggLT0gY29sdW1uTGVuZ3RoO1xuICAgICAgfVxuICAgICAgZWxzZSB7XG4gICAgICAgIHdpZHRocy5wdXNoKE1hdGgucm91bmQodG90YWxXaWR0aCAvIHRvdGFsTGVuZ3RoKSk7XG4gICAgICAgIHRvdGFsV2lkdGggLT0gTWF0aC5yb3VuZCgodG90YWxXaWR0aCAvIHRvdGFsTGVuZ3RoKSk7XG4gICAgICB9XG4gICAgICB0b3RhbExlbmd0aC0tO1xuICAgIH1cbiAgICB3aWR0aHMucHVzaCgnKicpO1xuXG4gICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgIGZvbnRTaXplOiA4LFxuICAgICAgdGFibGU6IHtcbiAgICAgICAgaGVhZGVyUm93czogMSxcbiAgICAgICAgd2lkdGhzLFxuICAgICAgICBib2R5OiBbdGFibGVIZWFkZXIsIC4uLnRhYmxlUm93c11cbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgZmlsbENvbG9yOiBpID0+IChpID09PSAwID8gQ09MT1JTLlBSSU1BUlkgOiBudWxsKSxcbiAgICAgICAgaExpbmVDb2xvcjogKCkgPT4gQ09MT1JTLlBSSU1BUlksXG4gICAgICAgIGhMaW5lV2lkdGg6ICgpID0+IDEsXG4gICAgICAgIHZMaW5lV2lkdGg6ICgpID0+IDBcbiAgICAgIH1cbiAgICB9KS5hZGROZXdMaW5lKCk7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBhZGRMaXN0KHt0aXRsZSwgbGlzdH06IHt0aXRsZTogc3RyaW5nIHwge3RleHQ6IHN0cmluZywgc3R5bGU6IHN0cmluZ30sIGxpc3Q6IChzdHJpbmcgfCB7dGV4dDogc3RyaW5nLCBzdHlsZTogc3RyaW5nfSlbXX0pe1xuICAgIHJldHVybiB0aGlzXG4gICAgICAuYWRkQ29udGVudFdpdGhOZXdMaW5lKHR5cGVvZiB0aXRsZSA9PT0gJ3N0cmluZycgPyB7dGV4dDogdGl0bGUsIHN0eWxlOiAnaDInfSA6IHRpdGxlKVxuICAgICAgLmFkZENvbnRlbnQoe3VsOiBsaXN0LmZpbHRlcihlbGVtZW50ID0+IGVsZW1lbnQpfSlcbiAgICAgIC5hZGROZXdMaW5lKCk7XG4gIH1cblxuICBhZGROZXdMaW5lKCl7XG4gICAgcmV0dXJuIHRoaXMuYWRkQ29udGVudCh7dGV4dDogJ1xcbid9KTtcbiAgfVxuXG4gIGFkZENvbnRlbnRXaXRoTmV3TGluZSh0aXRsZTogYW55KXtcbiAgICByZXR1cm4gdGhpcy5hZGRDb250ZW50KHRpdGxlKS5hZGROZXdMaW5lKCk7XG4gIH1cblxuICBhZGRBZ2VudHNGaWx0ZXJzKGFnZW50cyl7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzphZGRBZ2VudHNGaWx0ZXJzJyxcbiAgICAgIGBTdGFydGVkIHRvIHJlbmRlciB0aGUgYXV0aG9yaXplZCBhZ2VudHMgZmlsdGVyc2AsXG4gICAgICAnaW5mbydcbiAgICApO1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6YWRkQWdlbnRzRmlsdGVycycsXG4gICAgICBgYWdlbnRzOiAke2FnZW50c31gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICB0aGlzLmFkZE5ld0xpbmUoKTtcblxuICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICB0ZXh0OlxuICAgICAgICAnTk9URTogVGhpcyByZXBvcnQgb25seSBpbmNsdWRlcyB0aGUgYXV0aG9yaXplZCBhZ2VudHMgb2YgdGhlIHVzZXIgd2hvIGdlbmVyYXRlZCB0aGUgcmVwb3J0JyxcbiAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAxMCwgY29sb3I6IENPTE9SUy5QUklNQVJZIH0sXG4gICAgICBtYXJnaW46IFswLCAwLCAwLCA1XVxuICAgIH0pO1xuXG4gICAgLypUT0RPOiBUaGlzIHdpbGwgYmUgZW5hYmxlZCBieSBhIGNvbmZpZyovXG4gICAgLyogdGhpcy5hZGRDb250ZW50KHtcbiAgICAgIGZvbnRTaXplOiA4LFxuICAgICAgdGFibGU6IHtcbiAgICAgICAgd2lkdGhzOiBbJyonXSxcbiAgICAgICAgYm9keTogW1xuICAgICAgICAgIFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgIHN2ZzogZmlsdGVySWNvblJhdyxcbiAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMCxcbiAgICAgICAgICAgICAgICAgIGhlaWdodDogMTAsXG4gICAgICAgICAgICAgICAgICBtYXJnaW46IFs0MCwgNiwgMCwgMF1cbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgIHRleHQ6IGBBZ2VudCBJRHM6ICR7YWdlbnRzfWAgfHwgJy0nLFxuICAgICAgICAgICAgICAgICAgbWFyZ2luOiBbNDMsIDAsIDAsIDBdLFxuICAgICAgICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDgsIGNvbG9yOiAnIzMzMycgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgXVxuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgXVxuICAgICAgfSxcbiAgICAgIG1hcmdpbjogWy00MCwgMCwgLTQwLCAwXSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBmaWxsQ29sb3I6ICgpID0+IG51bGwsXG4gICAgICAgIGhMaW5lV2lkdGg6ICgpID0+IDAsXG4gICAgICAgIHZMaW5lV2lkdGg6ICgpID0+IDBcbiAgICAgIH1cbiAgICB9KTsgKi9cblxuICAgIHRoaXMuYWRkQ29udGVudCh7IHRleHQ6ICdcXG4nIH0pO1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6YWRkQWdlbnRzRmlsdGVycycsXG4gICAgICAnVGltZSByYW5nZSBhbmQgZmlsdGVycyByZW5kZXJlZCcsXG4gICAgICAnZGVidWcnXG4gICAgKTtcbiAgfVxuXG4gIGFzeW5jIHByaW50KHJlcG9ydFBhdGg6IHN0cmluZykge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBjb25maWd1cmF0aW9uID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuXG4gICAgICAgIGNvbnN0IHBhdGhUb0xvZ28gPSBnZXRDdXN0b21pemF0aW9uU2V0dGluZyhjb25maWd1cmF0aW9uLCAnY3VzdG9taXphdGlvbi5sb2dvLnJlcG9ydHMnKTtcbiAgICAgICAgY29uc3QgcGFnZUhlYWRlciA9IGdldEN1c3RvbWl6YXRpb25TZXR0aW5nKGNvbmZpZ3VyYXRpb24sICdjdXN0b21pemF0aW9uLnJlcG9ydHMuaGVhZGVyJyk7XG4gICAgICAgIGNvbnN0IHBhZ2VGb290ZXIgPSBnZXRDdXN0b21pemF0aW9uU2V0dGluZyhjb25maWd1cmF0aW9uLCAnY3VzdG9taXphdGlvbi5yZXBvcnRzLmZvb3RlcicpO1xuXG4gICAgICAgIGNvbnN0IGRvY3VtZW50ID0gdGhpcy5fcHJpbnRlci5jcmVhdGVQZGZLaXREb2N1bWVudCh7IC4uLnBhZ2VDb25maWd1cmF0aW9uKHsgcGF0aFRvTG9nbywgcGFnZUhlYWRlciwgcGFnZUZvb3RlciB9KSwgY29udGVudDogdGhpcy5fY29udGVudCB9KTtcblxuICAgICAgICBkb2N1bWVudC5vbignZXJyb3InLCByZWplY3QpO1xuICAgICAgICBkb2N1bWVudC5vbignZW5kJywgcmVzb2x2ZSk7XG5cbiAgICAgICAgZG9jdW1lbnQucGlwZShcbiAgICAgICAgICBmcy5jcmVhdGVXcml0ZVN0cmVhbShyZXBvcnRQYXRoKVxuICAgICAgICApO1xuICAgICAgICBkb2N1bWVudC5lbmQoKTtcbiAgICAgIH0gY2F0Y2ggKGV4KSB7XG4gICAgICAgIHJlamVjdChleCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgd2lkdGggb2YgYSBnaXZlbiBjb2x1bW5cbiAgICpcbiAgICogQHBhcmFtIGNvbHVtblxuICAgKiBAcGFyYW0gdGFibGVSb3dzXG4gICAqIEBwYXJhbSBzdGVwXG4gICAqIEByZXR1cm5zIHtudW1iZXJ9XG4gICAqL1xuICBnZXRDb2x1bW5XaWR0aChjb2x1bW4sIHRhYmxlUm93cywgaW5kZXgpe1xuICAgIGNvbnN0IHdpZHRoQ2hhcmFjdGVyID0gNTsgLy9taW4gd2lkdGggcGVyIGNoYXJhY3RlclxuXG4gICAgLy9HZXQgdGhlIGxvbmdlc3Qgcm93IHZhbHVlXG4gICAgY29uc3QgbWF4Um93TGVuZ3RoID0gdGFibGVSb3dzLnJlZHVjZSgobWF4TGVuZ3RoLCByb3cpPT57XG4gICAgICByZXR1cm4gKHJvd1tpbmRleF0udGV4dC5sZW5ndGggPiBtYXhMZW5ndGggPyByb3dbaW5kZXhdLnRleHQubGVuZ3RoIDogbWF4TGVuZ3RoKTtcbiAgICB9LDApO1xuXG4gICAgLy9HZXQgY29sdW1uIG5hbWUgbGVuZ3RoXG4gICAgY29uc3QgaGVhZGVyTGVuZ3RoID0gY29sdW1uLmxhYmVsLmxlbmd0aDtcblxuICAgIC8vVXNlIHRoZSBsb25nZXN0IHRvIGdldCB0aGUgY29sdW1uIHdpZHRoXG4gICAgY29uc3QgbWF4TGVuZ3RoID0gbWF4Um93TGVuZ3RoID4gaGVhZGVyTGVuZ3RoID8gbWF4Um93TGVuZ3RoIDogaGVhZGVyTGVuZ3RoO1xuXG4gICAgcmV0dXJuIG1heExlbmd0aCAqIHdpZHRoQ2hhcmFjdGVyO1xuICB9XG59XG4iXX0=