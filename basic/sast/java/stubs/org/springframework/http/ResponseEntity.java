package org.springframework.http;
public class ResponseEntity<T> {
    private T body;
    public ResponseEntity(T body) { this.body = body; }
    public static <T> ResponseEntity<T> ok(T body) { return new ResponseEntity<>(body); }
    public static <T> ResponseEntity<T> status(int code) { return new ResponseEntity<>(null); }
    public T getBody() { return body; }
}

