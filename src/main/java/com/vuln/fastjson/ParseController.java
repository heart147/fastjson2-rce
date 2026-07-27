package com.vuln.fastjson;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import com.alibaba.fastjson2.JSONReader;
import com.alibaba.fastjson2.reader.ObjectReader;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;

@Controller
public class ParseController {

    @GetMapping(value = "/debug", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> debug() throws Exception {
        Field f = com.alibaba.fastjson2.reader.ObjectReaderProvider.class.getDeclaredField("acceptHashCodes");
        f.setAccessible(true);
        long[] arr = (long[]) f.get(JSONFactory.getDefaultObjectReaderProvider());
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("count", arr.length);
        for (int i = 0; i < arr.length; i++)
            r.put("[" + i + "]", arr[i]);
        r.put("FNV_jar", com.alibaba.fastjson2.util.Fnv.hashCode64("jar"));
        return r;
    }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String index() {
        return "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Fastjson2 RCE</title></head><body>"
            + "<h2>Fastjson2 2.0.53 FNV-1a HashCollision RCE</h2>"
            + "<p>Vulnerable to PR #7695</p>"
            + "</body></html>";
    }

    @PostMapping(value = "/parse", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> parse(@RequestBody String payload) {
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            Object obj = JSON.parseObject(payload, Object.class);
            r.put("ok", true);
            r.put("class", obj == null ? "null" : obj.getClass().getName());
            r.put("result", String.valueOf(obj));
        } catch (Throwable e) {
            r.put("ok", false);
            r.put("error", e.getClass().getName() + ": " + e.getMessage());
        }
        return r;
    }

    // ObjectReaderSeeAlso path: Dto with @JSONType(seeAlso=...) triggers
    // ObjectReaderSeeAlso which auto-enables SupportAutoType
    @GetMapping(value = "/seereader", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> seeReader() {
        Map<String, Object> r = new LinkedHashMap<>();
        ObjectReader reader = JSONFactory.getDefaultObjectReaderProvider()
            .getObjectReader(Animal.class);
        r.put("readerClass", reader.getClass().getName());
        r.put("isSeeAlso", reader.getClass().getName().contains("ObjectReaderSeeAlso"));
        return r;
    }

    @PostMapping(value = "/parseAnimal", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> parseAnimal(@RequestBody String payload) {
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            // This triggers ObjectReaderSeeAlso → SupportAutoType auto-enabled
            Object obj = JSON.parseObject(payload, Animal.class);
            r.put("ok", true);
            r.put("class", obj == null ? "null" : obj.getClass().getName());
            r.put("result", String.valueOf(obj));
        } catch (Throwable e) {
            r.put("ok", false);
            r.put("error", e.getClass().getName() + ": " + e.getMessage());
        }
        return r;
    }
}
