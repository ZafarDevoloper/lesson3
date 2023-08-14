package com.example.task222.repository;

import com.example.task222.entity.Basket;
import com.example.task222.projection.CustomBasket;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "basket", excerptProjection = CustomBasket.class)
public interface BasketRepository extends JpaRepository<Basket,Integer> {
}
