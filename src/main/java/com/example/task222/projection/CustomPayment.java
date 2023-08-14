package com.example.task222.projection;

import com.example.task222.entity.Payment;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = Payment.class)
public interface CustomPayment {
    String getType();
}
