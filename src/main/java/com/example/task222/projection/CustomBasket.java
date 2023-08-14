package com.example.task222.projection;

import com.example.task222.entity.Basket;
import com.example.task222.entity.Product;
import org.springframework.data.rest.core.config.Projection;

import java.util.List;

@Projection(types = Basket.class)
public interface CustomBasket {
    Integer getId();
    List<Product> getProductList();

}
