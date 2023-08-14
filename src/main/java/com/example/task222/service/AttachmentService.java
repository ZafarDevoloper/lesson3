package com.example.task222.service;

import com.example.task222.entity.Attachment;
import com.example.task222.entity.AttachmentContent;
import com.example.task222.message.Result;
import com.example.task222.repository.AttachmentContentRepository;
import com.example.task222.repository.AttachmentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

@Service
public class AttachmentService {

    @Autowired
    AttachmentRepository attachmentRepository;
    @Autowired
    AttachmentContentRepository attachmentContentRepository;

    public List<Attachment> getAllAttachments() {
        return attachmentRepository.findAll();
    }

    public Result getById(Integer id) {
        Optional<Attachment> attachment = attachmentRepository.findById(id);
        return attachment.map(value -> new Result("Attachment with ID found", true, value)).orElseGet(() -> new Result("Attachment not found", false, null));
    }

    public Result create(MultipartHttpServletRequest request) throws IOException {
        boolean flag = false;
        Iterator<String> fileNames = request.getFileNames();
        while (fileNames.hasNext()) {
            MultipartFile file = request.getFile(fileNames.next());
            if (file != null) {
                flag = true;
                String originalFilename = file.getOriginalFilename();
                long size = file.getSize();
                String contentType = file.getContentType();
                Attachment attachment = new Attachment(null, originalFilename, size, contentType);
                Attachment savedAttachment = attachmentRepository.save(attachment);

                byte[] bytes = file.getBytes();
                AttachmentContent attachmentContent = new AttachmentContent(null, bytes, savedAttachment);
                attachmentContentRepository.save(attachmentContent);
            }
        }
        if(flag)
            return new Result("Files are uploaded successfully", true);
        return new Result("Files are not uploaded", false);
    }

    public Result delete(Integer id) {
        Optional<Attachment> attachment = attachmentRepository.findById(id);
        if (attachment.isPresent()) {
            attachmentRepository.deleteById(id);
            return new Result("Attachment is deleted successfully", true);
        }
        return new Result("Attachment not found", false);
    }

    public Result update(Integer id, MultipartHttpServletRequest request) throws IOException {
        boolean flag = false;
        Optional<Attachment> attachmentById = attachmentRepository.findById(id);
        if (attachmentById.isEmpty())
            return new Result("Attachment not found", false);
        Attachment attachment = attachmentById.get();
        AttachmentContent attachmentContent = attachmentContentRepository.findAttachmentContentByAttachment(attachment);

        Iterator<String> fileNames = request.getFileNames();
        while (fileNames.hasNext()){
            MultipartFile file = request.getFile(fileNames.next());
            if(file != null){
                flag = true;
                String originalFilename = file.getOriginalFilename();
                long size = file.getSize();
                String contentType = file.getContentType();
                attachment.setName(originalFilename);
                attachment.setSize(size);
                attachment.setContentType(contentType);
                Attachment savedAttachment = attachmentRepository.save(attachment);
                byte[] bytes = file.getBytes();
                attachmentContent.setAttachment(savedAttachment);
                attachmentContent.setBytes(bytes);
                attachmentContentRepository.save(attachmentContent);
            }
        }
        if (flag)
            return new Result("Files are updated successfully", true);
        return new Result("Error while uploading", false);
    }
}
