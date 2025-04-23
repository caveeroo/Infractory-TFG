package com.tfg.infractory.web.event;

import org.springframework.context.ApplicationEvent;
import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;

public class JoinSwarmEvent extends ApplicationEvent {
    private final Instance instance;
    private final SSHKey sshKey;

    public JoinSwarmEvent(Object source, Instance instance, SSHKey sshKey) {
        super(source);
        this.instance = instance;
        this.sshKey = sshKey;
    }

    public Instance getInstance() {
        return instance;
    }

    public SSHKey getSshKey() {
        return sshKey;
    }
}