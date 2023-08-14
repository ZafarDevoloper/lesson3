package com.example.task222.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.sql.Timestamp;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "orders")
public class Order {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    //@Column(nullable = false)
    private Timestamp date;

    @Column(nullable = false)
    private double totalPrice;

    @Column(nullable = false)
    private Integer orderNumber;

    @Column(nullable = false)
    private int status;

    @ManyToOne
    private Currency currency;

    @ManyToMany
    private Set<Payment> paymentTypes;
}
