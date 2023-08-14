package com.example.task222.repository;

import com.example.task222.entity.Category;
import com.example.task222.projection.CustomCategory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;

@RepositoryRestResource(path = "category", collectionResourceRel = "categoryList", excerptProjection = CustomCategory.class)
public interface CategoryRepository extends JpaRepository<Category, Integer> {

    @RestResource(path = "byName")
    Page<Category> findAllByName(@Param("name") String name, Pageable pageable); // /api/category/SEARCH/byName?name=PC

}
