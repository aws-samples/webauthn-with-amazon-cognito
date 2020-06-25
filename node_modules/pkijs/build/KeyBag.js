"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _PrivateKeyInfo = _interopRequireDefault(require("./PrivateKeyInfo.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

//**************************************************************************************

/**
 * Class from RFC5208
 */
class KeyBag extends _PrivateKeyInfo.default {
  //**********************************************************************************

  /**
   * Constructor for Attribute class
   * @param {Object} [parameters={}]
   * @param {Object} [parameters.schema] asn1js parsed value to initialize the class from
   */
  constructor(parameters = {}) {
    super(parameters);
  } //**********************************************************************************


} //**************************************************************************************


exports.default = KeyBag;
//# sourceMappingURL=KeyBag.js.map