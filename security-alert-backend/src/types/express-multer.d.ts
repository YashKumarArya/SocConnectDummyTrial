// Minimal ambient declarations so TypeScript compiles without installing @types/multer
// You should still install multer and its types in development: `npm install multer @types/multer -D`

declare namespace Express {
  export interface Request {
    // multer attaches this when using upload.single('file')
    file?: any;
    files?: any;
  }
}
