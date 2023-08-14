package com.example.task222.controller;

import com.example.task222.entity.Attachment;
import com.example.task222.message.Result;
import com.example.task222.service.AttachmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.List;

@RestController
@RequestMapping("/attachment")
public class AttachmentController {

    @Autowired
    AttachmentService attachmentService;

    @GetMapping
    public HttpEntity<?> getAllAttachments(){
        List<Attachment> allAttachments = attachmentService.getAllAttachments();
        return ResponseEntity.status(200).body(allAttachments);
    }

    @GetMapping("/upload/{id}")
    public HttpEntity<?> getById(@PathVariable Integer id){
        Result result = attachmentService.getById(id);
        return ResponseEntity.status(result.isSuccess()?200:405).body(result);
    }

    @PostMapping("/upload")
    public HttpEntity<?> createAttachment(MultipartHttpServletRequest request) throws IOException {
        Result result = attachmentService.create(request);
        return ResponseEntity.status(result.isSuccess()? 201 : 409).body(result);
    }

    @PutMapping("/{id}")
    public HttpEntity<?> updateAttachment(@PathVariable Integer id, MultipartHttpServletRequest request) throws IOException {
        Result result = attachmentService.update(id, request);
        return ResponseEntity.status(result.isSuccess()?202:400).body(result);
    }

    @DeleteMapping("/{id}")
    public HttpEntity<?> deleteById(@PathVariable Integer id){
        Result result = attachmentService.delete(id);
        return ResponseEntity.status(result.isSuccess() ? 204:400).body(result);
    }
}
