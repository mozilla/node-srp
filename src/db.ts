// in-memory db for testing and dev
// yes, there will be persistence :)
const data: {
  [key: string]: any
} = {}

export const store = (key: string, value: any, callback: Function): Function => {
  data[key] = value
  return callback(null, true)
}

export const fetch = (key: string, callback: Function): Function => {
  return callback(null, data[key])
}
