// Minimal ambient type to silence missing ioredis module errors when it's optional
declare module 'ioredis' {
  class Redis {
    constructor(uri?: string);
    on(event: string, cb: (...args: any[]) => void): void;
    set(...args: any[]): Promise<any>;
    del(...args: any[]): Promise<any>;
  }
  export = Redis;
}
