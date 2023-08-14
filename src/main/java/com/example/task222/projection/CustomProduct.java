package com.example.task222.projection;

import com.example.task222.entity.*;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = Product.class)
public interface CustomProduct {

    String getName();
    String getDefinition();
    Double getPrice();
    Integer getQuantity();
    Category getCategory();
    Attachment getAttachmentList();
    Characteristics getCharacteristicsList();
    Currency getCurrency();

}
