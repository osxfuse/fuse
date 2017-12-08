/*
 FUSE: Filesystem in Userspace
 Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 
 This program can be distributed under the terms of the GNU LGPLv2.
 See the file COPYING.LIB.
 */

/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2012 Benjamin Fleischer
 * Copyright (c) 2017 Dave MacLachlan/Google Inc.
 */

#include "config.h"

#if HAVE_DISPATCH_DISPATCH_H

#include "fuse_i.h"
#include "fuse_lowlevel.h"

#include <dispatch/dispatch.h>

#include <stdio.h>
#include <errno.h>
#include <signal.h>

static register_signal_source(int sig,
                              dispatch_queue_t queue,
                              struct fuse_session *se) {
  signal(sig, SIG_IGN);
  dispatch_source_t sig_src =
  dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, sig, 0, queue);
  dispatch_source_set_event_handler(sig_src, ^{
#ifdef __APPLE__
    struct fuse_chan *ch = fuse_session_next_chan(se, NULL);
    if (ch)
      fuse_unmount(NULL, ch);
#else
    fuse_session_exit(se);
#endif
  });
  dispatch_resume(sig_src);
}

int fuse_session_loop_dispatch(struct fuse_session *se)
{
  int res = 0;
  struct fuse_chan *ch = fuse_session_next_chan(se, NULL);
  size_t bufsize = fuse_chan_bufsize(ch);
  
  dispatch_queue_t queue =
  dispatch_queue_create("fuse_session", DISPATCH_QUEUE_CONCURRENT);
  dispatch_group_t group = dispatch_group_create();
  
  // Set up signal handling.
  int signals[] = { SIGTERM, SIGINT, SIGHUP, SIGQUIT };
  for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
    register_signal_source(signals[i], queue, se);
  }
  
  char *buf = (char *) malloc(bufsize);
  if (!buf) {
    fprintf(stderr, "fuse: failed to allocate read buffer\n");
    return -1;
  }
  while (!fuse_session_exited(se)) {
    
    struct fuse_chan *tmpch = ch;
    struct fuse_buf fbuf = {
      .mem = buf,
      .size = bufsize,
    };
    
    res = fuse_session_receive_buf(se, &fbuf, &tmpch);
    
    if (res == -EINTR) {
      continue;
    }
    if (res <= 0) {
      break;
    }
    
    char *newbuf = (char *)malloc(res);
    if (!newbuf) {
      fprintf(stderr, "fuse: failed to allocate process buffer\n");
      res = -1;
      break;
    }
    memcpy(newbuf, fbuf.mem, res);
    fbuf.mem = newbuf;
    fbuf.size = res;
    dispatch_group_async(group, queue, ^{
      fuse_session_process_buf(se, &fbuf, tmpch);
      free(fbuf.mem);
    });
  }
  dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
  dispatch_release(group);
  dispatch_release(queue);
  free(buf);
  fuse_session_reset(se);
  return res < 0 ? -1 : 0;
}

int fuse_loop_dispatch(struct fuse *f) {
  return fuse_session_loop_dispatch(fuse_get_session(f));
}

#endif // HAVE_DISPATCH_DISPATCH_H
