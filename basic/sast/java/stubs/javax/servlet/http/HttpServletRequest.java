package javax.servlet.http;
import java.io.*;
public interface HttpServletRequest {
    String getParameter(String name);
    String getHeader(String name);
    InputStream getInputStream() throws IOException;
}
