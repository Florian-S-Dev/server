const {port, hostname, protocol, pathname} = window.location;
const slashes = protocol.concat('//');
const path = pathname.endsWith('/') ? pathname : pathname.substring(0, pathname.lastIndexOf('/'));
export const url = slashes.concat(port ? hostname.concat(':', port) : hostname) + path;
export const urlWithSlash =
    process.env.NODE_ENV === 'development'
        ? 'http://localhost:5050/'
        : url.endsWith('/')
        ? url
        : url.concat('/');
