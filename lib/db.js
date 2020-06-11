"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.fetch = exports.store = void 0;
// in-memory db for testing and dev
// yes, there will be persistence :)
const data = {};
exports.store = (key, value, callback) => {
    data[key] = value;
    return callback(null, true);
};
exports.fetch = (key, callback) => {
    return callback(null, data[key]);
};
