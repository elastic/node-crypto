module.exports = {
  preset: 'ts-jest',
  rootDir: '.',
  testEnvironment: 'node',
  collectCoverageFrom: [
    'src/**/*.ts'
  ],
  coveragePathIgnorePatterns: [
    '<rootDir>/node_modules'
  ],
  "moduleFileExtensions": [
    "js",
    "ts"
  ],
  coverageReporters: [
    'json',
    'lcov',
    'text'
  ],
  coverageThreshold: {
    global: {
      branches: 86,
      functions: 100,
      lines: 93,
      statements: 93,
    }
  }
};