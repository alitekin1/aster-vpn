# Apply only to the pinned Xray version; abort if upstream context changes.
from pathlib import Path
path = Path('.deps/xray/proxy/freedom/freedom.go')
source = path.read_text()
old = '''\t\tif err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
\t\t\treturn errors.New("failed to process request").Base(err)
\t\t}

\t\treturn nil'''
new = '''\t\tif err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
\t\t\treturn errors.New("failed to process request").Base(err)
\t\t}

        // Aster: propagate successful TCP uplink EOF without closing the response.
        if destination.Network == net.Network_TCP {
            var rawConn net.Conn = conn
            if counter, ok := rawConn.(*stat.CounterConnection); ok { rawConn = counter.Connection }
            if half, ok := rawConn.(interface { CloseWrite() error }); ok { _ = half.CloseWrite() }
        }
\t\treturn nil'''
assert source.count(old) == 1, 'Pinned freedom half-close patch context changed'
path.write_text(source.replace(old, new))
