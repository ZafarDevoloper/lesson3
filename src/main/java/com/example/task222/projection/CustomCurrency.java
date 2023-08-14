package com.example.task222.projection;

import com.example.task222.entity.Currency;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = Currency.class)
public interface CustomCurrency {

    String getName();
}
