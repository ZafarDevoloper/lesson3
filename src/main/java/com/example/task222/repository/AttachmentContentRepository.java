package com.example.task222.repository;

import com.example.task222.entity.Attachment;
import com.example.task222.entity.AttachmentContent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "attachmentContent")
public interface AttachmentContentRepository extends JpaRepository<AttachmentContent, Integer> {
    AttachmentContent findAttachmentContentByAttachment(Attachment attachment);
}
