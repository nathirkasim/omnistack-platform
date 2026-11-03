package javax.servlet.http;
import java.io.*;
public interface HttpServletResponse {
    PrintWriter getWriter() throws IOException;
    void sendRedirect(String location) throws IOException;
    void setContentType(String type);
    void setStatus(int sc);
    void setHeader(String name, String value);
}
