package com.example.task222.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.List;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String code;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String definition;

    @Column(nullable = false)
    private Double price;

    @Column(nullable = false)
    private Integer quantity;

    @Column(nullable = false)
    private boolean active;

    @ManyToOne
    private Category category;

    @ManyToMany
    private List<Attachment> attachmentList;

    @ManyToMany
    private List<Characteristics> characteristicsList;

    @ManyToOne
    private Currency currency;
}
