const path = require('path')

module.exports = {
  entry: './index.js',
  devtool: 'source-map',
  target: 'web',
  output: {
    libraryTarget: 'var',
    library: 'TallyLabAccess',
    filename: 'tallylab-orbitdb-access.min.js',
    path: path.resolve('dist')
  }
}
