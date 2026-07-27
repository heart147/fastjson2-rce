package com.vuln.fastjson;

import com.alibaba.fastjson2.annotation.JSONType;

// Polymorphic DTO with seeAlso — triggers ObjectReaderSeeAlso with SupportAutoType
@JSONType(seeAlso = {Dog.class, Cat.class})
public class Animal {
    private String name;
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}

class Dog extends Animal {
    private int age;
    public int getAge() { return age; }
    public void setAge(int age) { this.age = age; }
}

class Cat extends Animal {
    private String color;
    public String getColor() { return color; }
    public void setColor(String color) { this.color = color; }
}
