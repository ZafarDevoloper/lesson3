package com.example.task222.projection;

import com.example.task222.entity.Category;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = Category.class)
public interface CustomCategory {

    Integer getId();
    String getName();
    Integer getParentCategory();
    Integer getAttachment();

}
