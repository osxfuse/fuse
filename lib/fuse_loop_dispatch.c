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

// Register a signal source for sig on queue that will clean up the session.
// Returns the signal source, or NULL on failure.
// Caller reponsible for releasing source.
static dispatch_source_t register_signal_source(int sig,
                                                dispatch_queue_t queue,
                                                struct fuse_session *se) {
  void (*old_signal)(int) = signal(sig, SIG_IGN);
  if (old_signal == SIG_ERR) {
    fprintf(stderr, "fuse: failed to set signal %d\n", sig);
    return NULL;
  }
  dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,
                                                 sig, 0, queue);
  if (!src) {
    fprintf(stderr, "fuse: unable to create signal source for %d\n", sig);
    return NULL;
  }
  dispatch_source_set_event_handler(src, ^{
#ifdef __APPLE__
    struct fuse_chan *ch = fuse_session_next_chan(se, NULL);
    if (ch)
      fuse_unmount(NULL, ch);
#else
    fuse_session_exit(se);
#endif
  });
  dispatch_resume(src);
  return src;
}

int fuse_session_loop_dispatch(struct fuse_session *se)
{
  int res = 0;
  struct fuse_chan *ch = fuse_session_next_chan(se, NULL);
  size_t bufsize = fuse_chan_bufsize(ch);
  
  dispatch_queue_t queue = dispatch_queue_create("fuse_session",
                                                 DISPATCH_QUEUE_CONCURRENT);
  if (!queue) {
    fprintf(stderr, "fuse: failed to allocate session loop queue\n");
    res = -1;
    goto no_queue;
  }
  dispatch_group_t group = dispatch_group_create();
  if (!group) {
    fprintf(stderr, "fuse: failed to allocate session loop group\n");
    res = -1;
    goto no_group;
  }

  // Set up signal handling.
  int signals[] = { SIGTERM, SIGINT, SIGHUP, SIGQUIT };
  const int signal_count = sizeof(signals) / sizeof(signals[0]);
  dispatch_source_t signal_sources[signal_count] = { NULL };
  for (int i = 0; i < signal_count; ++i) {
    signal_sources[i] = register_signal_source(signals[i], queue, se);
    if (!signal_sources[i]) {
      goto no_signal_sources;
    }
  }
  
  char *buf = (char *) malloc(bufsize);
  if (!buf) {
    fprintf(stderr, "fuse: failed to allocate session loop read buffer\n");
    res = -1;
    goto no_buf;
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
    
    // Create a new buffer and copy because buf is huge, and the data
    // transferred is usually orders of magnitude smaller.
    char *newbuf = (char *) malloc(res);
    if (!newbuf) {
      fprintf(stderr, "fuse: failed to allocate session loop process buffer\n");
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
  if(dispatch_group_wait(group, DISPATCH_TIME_FOREVER) != 0) {
    fprintf(stderr, "fuse: dispatch_group_wait timed out\n");
    res = -1;
  }
  free(buf);

no_signal_sources:
  for (int i = 0; i < signal_count; ++i) {
    if (signal_sources[i]) {
      dispatch_release(signal_sources[i]);
    }
  }

no_buf:
  dispatch_release(group);

no_group:
  dispatch_release(queue);
  
no_queue:
  fuse_session_reset(se);
  return res < 0 ? -1 : 0;
}

int fuse_loop_dispatch(struct fuse *f) {
  return fuse_session_loop_dispatch(fuse_get_session(f));
}

#endif // HAVE_DISPATCH_DISPATCH_H
